use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{BackendError, Database, Durability, ReadableDatabase, StorageBackend, TableDefinition};
use thiserror::Error;

const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("policy");
pub type ReadReply = Receiver<Result<Option<Vec<u8>>, StorageError>>;
pub type WriteReply = Receiver<Result<(), StorageError>>;
type ScanResult = Result<Vec<(String, Vec<u8>)>, StorageError>;
pub type ScanReply = Receiver<ScanResult>;

enum Command {
    Get {
        key: String,
        response: SyncSender<Result<Option<Vec<u8>>, StorageError>>,
    },
    Put {
        key: String,
        value: Vec<u8>,
        response: SyncSender<Result<(), StorageError>>,
    },
    Delete {
        key: String,
        response: SyncSender<Result<(), StorageError>>,
    },
    Apply {
        changes: Vec<(String, Option<Vec<u8>>)>,
        response: SyncSender<Result<(), StorageError>>,
    },
    Scan {
        prefix: String,
        limit: usize,
        response: SyncSender<ScanResult>,
    },
    Backup {
        destination: PathBuf,
        response: SyncSender<Result<(), StorageError>>,
    },
    Stop {
        response: SyncSender<()>,
    },
}

pub struct StorageWorker {
    sender: SyncSender<Command>,
    worker: Option<JoinHandle<()>>,
    stopping: Option<Receiver<()>>,
}

impl StorageWorker {
    pub fn open(
        path: PathBuf,
        cache_bytes: usize,
        max_database_bytes: u64,
        queue_capacity: usize,
    ) -> Result<Self, StorageError> {
        if cache_bytes == 0 || max_database_bytes == 0 || queue_capacity == 0 {
            return Err(StorageError::Invalid);
        }
        prepare_path(&path)?;
        let database = open_database(&path, cache_bytes, max_database_bytes)?;
        let (sender, receiver) = sync_channel(queue_capacity);
        let worker = thread::Builder::new()
            .name("snolc-policy-storage".into())
            .spawn(move || run(database, receiver, path, cache_bytes, max_database_bytes))?;
        Ok(Self {
            sender,
            worker: Some(worker),
            stopping: None,
        })
    }

    pub fn get(&self, key: String) -> Result<ReadReply, StorageError> {
        validate_key(&key)?;
        let (sender, receiver) = sync_channel(1);
        self.send(Command::Get {
            key,
            response: sender,
        })?;
        Ok(receiver)
    }

    pub fn put(&self, key: String, value: Vec<u8>) -> Result<WriteReply, StorageError> {
        validate_key(&key)?;
        let (sender, receiver) = sync_channel(1);
        self.send(Command::Put {
            key,
            value,
            response: sender,
        })?;
        Ok(receiver)
    }

    pub fn delete(&self, key: String) -> Result<WriteReply, StorageError> {
        validate_key(&key)?;
        let (sender, receiver) = sync_channel(1);
        self.send(Command::Delete {
            key,
            response: sender,
        })?;
        Ok(receiver)
    }

    pub fn apply(
        &self,
        changes: Vec<(String, Option<Vec<u8>>)>,
    ) -> Result<WriteReply, StorageError> {
        if changes.is_empty() {
            return Err(StorageError::Invalid);
        }
        for (key, _) in &changes {
            validate_key(key)?;
        }
        let (sender, receiver) = sync_channel(1);
        self.send(Command::Apply {
            changes,
            response: sender,
        })?;
        Ok(receiver)
    }

    pub fn scan(&self, prefix: String, limit: usize) -> Result<ScanReply, StorageError> {
        validate_prefix(&prefix)?;
        if limit == 0 {
            return Err(StorageError::Invalid);
        }
        let (sender, receiver) = sync_channel(1);
        self.send(Command::Scan {
            prefix,
            limit,
            response: sender,
        })?;
        Ok(receiver)
    }

    pub fn backup(&self, destination: PathBuf) -> Result<WriteReply, StorageError> {
        if !destination.is_absolute() {
            return Err(StorageError::Invalid);
        }
        let (response, reply) = sync_channel(1);
        self.send(Command::Backup {
            destination,
            response,
        })?;
        Ok(reply)
    }

    pub fn start_shutdown(&mut self) -> Result<(), StorageError> {
        if self.stopping.is_some() {
            return Ok(());
        }
        let (response, reply) = sync_channel(1);
        self.send(Command::Stop { response })?;
        self.stopping = Some(reply);
        Ok(())
    }

    pub fn poll_shutdown(&mut self) -> Result<bool, StorageError> {
        self.start_shutdown()?;
        let Some(stopping) = &self.stopping else {
            return Err(StorageError::Stopped);
        };
        match stopping.try_recv() {
            Ok(()) => {
                self.stopping = None;
                if let Some(worker) = self.worker.take() {
                    worker.join().map_err(|_| StorageError::Stopped)?;
                }
                Ok(true)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(StorageError::Stopped),
        }
    }

    fn send(&self, command: Command) -> Result<(), StorageError> {
        if self.stopping.is_some() {
            return Err(StorageError::Stopped);
        }
        self.sender.try_send(command).map_err(|error| match error {
            TrySendError::Full(_) => StorageError::QueueFull,
            TrySendError::Disconnected(_) => StorageError::Stopped,
        })
    }
}

impl Drop for StorageWorker {
    fn drop(&mut self) {
        if self.stopping.is_none() {
            let (response, reply) = sync_channel(1);
            if self.sender.send(Command::Stop { response }).is_ok() {
                self.stopping = Some(reply);
            }
        }
        if let Some(stopping) = self.stopping.take() {
            let _ = stopping.recv();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run(
    database: Database,
    receiver: Receiver<Command>,
    path: PathBuf,
    cache_bytes: usize,
    max_database_bytes: u64,
) {
    let mut database = Some(database);
    let mut stop = None;
    while let Ok(command) = receiver.recv() {
        let Some(open) = database.as_ref() else {
            break;
        };
        match command {
            Command::Get { key, response } => {
                let _ = response.send(get_value(open, &key));
            }
            Command::Put {
                key,
                value,
                response,
            } => {
                let result = put_value(open, &key, &value);
                let _ = response.send(result);
            }
            Command::Delete { key, response } => {
                let _ = response.send(delete_value(open, &key));
            }
            Command::Apply { changes, response } => {
                let result = apply_values(open, &changes);
                let _ = response.send(result);
            }
            Command::Scan {
                prefix,
                limit,
                response,
            } => {
                let _ = response.send(scan_values(open, &prefix, limit));
            }
            Command::Backup {
                destination,
                response,
            } => {
                drop(database.take());
                let backup =
                    backup_closed_database(&path, &destination, cache_bytes, max_database_bytes);
                match open_database(&path, cache_bytes, max_database_bytes) {
                    Ok(open) => database = Some(open),
                    Err(error) => {
                        let _ = response.send(Err(error));
                        break;
                    }
                }
                let _ = response.send(backup);
            }
            Command::Stop { response } => {
                stop = Some(response);
                break;
            }
        }
    }
    drop(database.take());
    if let Some(response) = stop {
        let _ = response.send(());
    }
}

fn open_database(
    path: &Path,
    cache_bytes: usize,
    max_database_bytes: u64,
) -> Result<Database, StorageError> {
    let backend = LockedFileBackend::open(path, max_database_bytes)?;
    let mut builder = Database::builder();
    builder.set_cache_size(cache_bytes);
    let database = builder
        .create_with_backend(backend)
        .map_err(database_error)?;
    let mut transaction = database.begin_write().map_err(transaction_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|error| StorageError::Database(error.to_string()))?;
    transaction.open_table(KV).map_err(table_error)?;
    transaction.commit().map_err(commit_error)?;
    Ok(database)
}

fn backup_closed_database(
    source: &Path,
    destination: &Path,
    cache_bytes: usize,
    max_database_bytes: u64,
) -> Result<(), StorageError> {
    if source == destination || destination.exists() {
        return Err(StorageError::Invalid);
    }
    prepare_path(destination)?;
    let temporary = destination.with_extension(format!(
        "backup-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StorageError::Invalid)?
            .as_nanos()
    ));
    let result = (|| {
        copy_private_file(source, &temporary, max_database_bytes)?;
        verify_database(&temporary, cache_bytes)?;
        fs::rename(&temporary, destination)?;
        sync_parent(destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn restore_stopped_database(
    backup: &Path,
    destination: &Path,
    cache_bytes: usize,
    max_database_bytes: u64,
) -> Result<(), StorageError> {
    if backup == destination || !backup.is_file() || !destination.is_absolute() {
        return Err(StorageError::Invalid);
    }
    if fs::metadata(backup)?.len() > max_database_bytes {
        return Err(StorageError::Limit);
    }
    verify_database(backup, cache_bytes)?;
    prepare_path(destination)?;
    let temporary = destination.with_extension(format!(
        "restore-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StorageError::Invalid)?
            .as_nanos()
    ));
    let result = (|| {
        copy_private_file(backup, &temporary, max_database_bytes)?;
        verify_database(&temporary, cache_bytes)?;
        fs::rename(&temporary, destination)?;
        sync_parent(destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn copy_private_file(
    source: &Path,
    destination: &Path,
    max_bytes: u64,
) -> Result<(), StorageError> {
    let length = fs::metadata(source)?.len();
    if length > max_bytes {
        return Err(StorageError::Limit);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(destination)?;
    let mut input = File::open(source)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn verify_database(path: &Path, cache_bytes: usize) -> Result<(), StorageError> {
    let mut builder = Database::builder();
    builder.set_cache_size(cache_bytes);
    let database = builder.open_read_only(path).map_err(database_error)?;
    let transaction = database.begin_read().map_err(transaction_error)?;
    transaction.open_table(KV).map_err(table_error)?;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), StorageError> {
    let parent = path.parent().ok_or(StorageError::Invalid)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn get_value(database: &Database, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
    let transaction = database.begin_read().map_err(transaction_error)?;
    let table = transaction.open_table(KV).map_err(table_error)?;
    let value = table.get(key).map_err(storage_error)?;
    Ok(value.map(|value| value.value().to_vec()))
}

fn put_value(database: &Database, key: &str, value: &[u8]) -> Result<(), StorageError> {
    let mut transaction = database.begin_write().map_err(transaction_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|error| StorageError::Database(error.to_string()))?;
    {
        let mut table = transaction.open_table(KV).map_err(table_error)?;
        table.insert(key, value).map_err(storage_error)?;
    }
    transaction.commit().map_err(commit_error)
}

fn delete_value(database: &Database, key: &str) -> Result<(), StorageError> {
    let mut transaction = database.begin_write().map_err(transaction_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|error| StorageError::Database(error.to_string()))?;
    {
        let mut table = transaction.open_table(KV).map_err(table_error)?;
        table.remove(key).map_err(storage_error)?;
    }
    transaction.commit().map_err(commit_error)
}

fn apply_values(
    database: &Database,
    changes: &[(String, Option<Vec<u8>>)],
) -> Result<(), StorageError> {
    let mut transaction = database.begin_write().map_err(transaction_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|error| StorageError::Database(error.to_string()))?;
    {
        let mut table = transaction.open_table(KV).map_err(table_error)?;
        for (key, value) in changes {
            if let Some(value) = value {
                table
                    .insert(key.as_str(), value.as_slice())
                    .map_err(storage_error)?;
            } else {
                table.remove(key.as_str()).map_err(storage_error)?;
            }
        }
    }
    transaction.commit().map_err(commit_error)
}

fn scan_values(
    database: &Database,
    prefix: &str,
    limit: usize,
) -> Result<Vec<(String, Vec<u8>)>, StorageError> {
    let transaction = database.begin_read().map_err(transaction_error)?;
    let table = transaction.open_table(KV).map_err(table_error)?;
    let end = prefix_end(prefix)?;
    let entries = table.range(prefix..end.as_str()).map_err(storage_error)?;
    let mut output = Vec::new();
    for entry in entries {
        if output.len() == limit {
            return Err(StorageError::Limit);
        }
        let (key, value) = entry.map_err(storage_error)?;
        output.push((key.value().to_owned(), value.value().to_vec()));
    }
    Ok(output)
}

fn validate_key(key: &str) -> Result<(), StorageError> {
    if key.is_empty()
        || key.len() > 512
        || !["meta/", "user/", "credential/", "client/"]
            .iter()
            .any(|prefix| key.starts_with(prefix))
    {
        return Err(StorageError::Invalid);
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<(), StorageError> {
    if ["meta/", "user/", "credential/", "client/"].contains(&prefix) {
        Ok(())
    } else {
        Err(StorageError::Invalid)
    }
}

fn prefix_end(prefix: &str) -> Result<String, StorageError> {
    validate_prefix(prefix)?;
    let mut bytes = prefix.as_bytes().to_vec();
    let last = bytes.last_mut().ok_or(StorageError::Invalid)?;
    *last = last.checked_add(1).ok_or(StorageError::Invalid)?;
    String::from_utf8(bytes).map_err(|_| StorageError::Invalid)
}

fn prepare_path(path: &Path) -> Result<(), StorageError> {
    let directory = path.parent().ok_or(StorageError::Invalid)?;
    #[cfg(unix)]
    let existed = directory.exists();
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if existed {
            if fs::metadata(directory)?.permissions().mode() & 0o077 != 0 {
                return Err(StorageError::Permissions);
            }
        } else {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

struct LockedFileBackend {
    file: File,
    max_bytes: u64,
    locked: AtomicBool,
}

impl LockedFileBackend {
    fn open(path: &Path, max_bytes: u64) -> Result<Self, StorageError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file.metadata()?.permissions().mode() & 0o077 != 0 {
                return Err(StorageError::Permissions);
            }
        }
        if file.metadata()?.len() > max_bytes {
            return Err(StorageError::Limit);
        }
        Ok(Self {
            file,
            max_bytes,
            locked: AtomicBool::new(false),
        })
    }

    fn whole_range(start: &Bound<u64>, end: &Bound<u64>) -> bool {
        matches!(start, Bound::Unbounded | Bound::Included(0)) && *end == Bound::Unbounded
    }

    fn check_end(&self, offset: u64, length: usize) -> io::Result<()> {
        let length = u64::try_from(length)
            .map_err(|_| io::Error::new(io::ErrorKind::FileTooLarge, "database size overflow"))?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::FileTooLarge, "database size overflow"))?;
        if end > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "database size limit exhausted",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for LockedFileBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedFileBackend")
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

impl StorageBackend for LockedFileBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn read(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        read_exact_at(&self.file, offset, output)
    }

    fn set_len(&self, length: u64) -> io::Result<()> {
        self.check_end(
            0,
            usize::try_from(length).map_err(|_| {
                io::Error::new(io::ErrorKind::FileTooLarge, "database size overflow")
            })?,
        )?;
        self.file.set_len(length)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.check_end(offset, data.len())?;
        write_all_at(&self.file, offset, data)
    }

    fn try_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> {
        if !Self::whole_range(&start, &end) {
            return Err(BackendError::Unsupported);
        }
        match self.file.try_lock() {
            Ok(()) => {
                self.locked.store(true, Ordering::Release);
                Ok(true)
            }
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }

    fn try_lock_shared_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> Result<bool, BackendError> {
        if !Self::whole_range(&start, &end) {
            return Err(BackendError::Unsupported);
        }
        match self.file.try_lock_shared() {
            Ok(()) => {
                self.locked.store(true, Ordering::Release);
                Ok(true)
            }
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }

    fn unlock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
        if !Self::whole_range(&start, &end) {
            return Err(BackendError::Unsupported);
        }
        if self.locked.swap(false, Ordering::AcqRel) {
            self.file.unlock()?;
        }
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        if self.locked.swap(false, Ordering::AcqRel) {
            self.file.unlock()?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, mut offset: u64, mut output: &mut [u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !output.is_empty() {
        match file.read_at(output, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => {
                offset += read as u64;
                output = &mut output[read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_all_at(file: &File, mut offset: u64, mut data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !data.is_empty() {
        match file.write_at(data, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => {
                offset += written as u64;
                data = &data[written..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut output: &mut [u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !output.is_empty() {
        match file.seek_read(output, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => {
                offset += read as u64;
                output = &mut output[read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn write_all_at(file: &File, mut offset: u64, mut data: &[u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !data.is_empty() {
        match file.seek_write(data, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => {
                offset += written as u64;
                data = &data[written..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
compile_error!("policy-local storage requires positional file I/O");

fn database_error(error: redb::DatabaseError) -> StorageError {
    StorageError::Database(error.to_string())
}

fn transaction_error(error: redb::TransactionError) -> StorageError {
    StorageError::Database(error.to_string())
}

fn table_error(error: redb::TableError) -> StorageError {
    StorageError::Database(error.to_string())
}

fn storage_error(error: redb::StorageError) -> StorageError {
    StorageError::Database(error.to_string())
}

fn commit_error(error: redb::CommitError) -> StorageError {
    StorageError::Database(error.to_string())
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage options or key are invalid")]
    Invalid,
    #[error("storage queue is full")]
    QueueFull,
    #[error("storage worker stopped")]
    Stopped,
    #[error("database size limit is exhausted")]
    Limit,
    #[error("storage directory permissions are not private")]
    Permissions,
    #[error("storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("database failed: {0}")]
    Database(String),
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn path() -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "snolc-policy-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .join("policy.redb")
    }

    #[test]
    fn persists_values_with_bounded_commands() {
        let path = path();
        {
            let worker = StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 4).unwrap();
            worker
                .put("user/01".into(), b"record".to_vec())
                .unwrap()
                .recv()
                .unwrap()
                .unwrap();
            assert_eq!(
                worker
                    .get("user/01".into())
                    .unwrap()
                    .recv()
                    .unwrap()
                    .unwrap(),
                Some(b"record".to_vec())
            );
        }
        let worker = StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 4).unwrap();
        assert_eq!(
            worker
                .get("user/01".into())
                .unwrap()
                .recv()
                .unwrap()
                .unwrap(),
            Some(b"record".to_vec())
        );
        drop(worker);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn rejects_foreign_key_namespace() {
        let path = path();
        let worker = StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 1).unwrap();
        assert!(matches!(
            worker.get("other/key".into()),
            Err(StorageError::Invalid)
        ));
        drop(worker);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn applies_multiple_keys_in_one_transaction() {
        let path = path();
        let worker = StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 2).unwrap();
        worker
            .apply(vec![
                ("user/01".into(), Some(b"user".to_vec())),
                ("client/panel".into(), Some(b"receipt".to_vec())),
            ])
            .unwrap()
            .recv()
            .unwrap()
            .unwrap();
        assert!(
            worker
                .get("user/01".into())
                .unwrap()
                .recv()
                .unwrap()
                .unwrap()
                .is_some()
        );
        assert!(
            worker
                .get("client/panel".into())
                .unwrap()
                .recv()
                .unwrap()
                .unwrap()
                .is_some()
        );
        drop(worker);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn refuses_a_second_database_owner() {
        let path = path();
        let first = StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 2).unwrap();
        assert!(matches!(
            StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 2),
            Err(StorageError::Database(_))
        ));
        drop(first);
        StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 2).unwrap();
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn backend_rejects_growth_before_writing() {
        let path = path();
        prepare_path(&path).unwrap();
        let backend = LockedFileBackend::open(&path, 8).unwrap();
        backend.write(0, b"12345678").unwrap();
        assert_eq!(backend.len().unwrap(), 8);
        assert_eq!(
            backend.write(8, b"9").unwrap_err().kind(),
            io::ErrorKind::FileTooLarge
        );
        assert_eq!(backend.len().unwrap(), 8);
        drop(backend);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn scans_one_namespace_with_a_hard_limit() {
        let path = path();
        let worker = StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 4).unwrap();
        worker
            .apply(vec![
                ("client/a".into(), Some(b"one".to_vec())),
                ("client/b".into(), Some(b"two".to_vec())),
                ("user/a".into(), Some(b"ignored".to_vec())),
            ])
            .unwrap()
            .recv()
            .unwrap()
            .unwrap();
        let entries = worker
            .scan("client/".into(), 2)
            .unwrap()
            .recv()
            .unwrap()
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|(key, _)| key.starts_with("client/")));
        assert!(matches!(
            worker.scan("client/".into(), 1).unwrap().recv().unwrap(),
            Err(StorageError::Limit)
        ));
        drop(worker);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn shutdown_can_be_polled_without_waiting_on_the_worker() {
        let path = path();
        let mut worker = StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 2).unwrap();
        worker.start_shutdown().unwrap();
        while !worker.poll_shutdown().unwrap() {
            std::thread::yield_now();
        }
        assert!(matches!(
            worker.get("user/01".into()),
            Err(StorageError::Stopped)
        ));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn backup_closes_verifies_and_reopens_the_database() {
        let path = path();
        let backup = path.parent().unwrap().join("backup.redb");
        let worker = StorageWorker::open(path.clone(), 1_048_576, 16_777_216, 4).unwrap();
        worker
            .put("user/01".into(), b"before".to_vec())
            .unwrap()
            .recv()
            .unwrap()
            .unwrap();
        worker
            .backup(backup.clone())
            .unwrap()
            .recv()
            .unwrap()
            .unwrap();
        worker
            .put("user/02".into(), b"after".to_vec())
            .unwrap()
            .recv()
            .unwrap()
            .unwrap();
        drop(worker);

        let backup_worker = StorageWorker::open(backup.clone(), 1_048_576, 16_777_216, 2).unwrap();
        assert_eq!(
            backup_worker
                .get("user/01".into())
                .unwrap()
                .recv()
                .unwrap()
                .unwrap(),
            Some(b"before".to_vec())
        );
        assert_eq!(
            backup_worker
                .get("user/02".into())
                .unwrap()
                .recv()
                .unwrap()
                .unwrap(),
            None
        );
        drop(backup_worker);

        let restored = path.parent().unwrap().join("restored/policy.redb");
        restore_stopped_database(&backup, &restored, 1_048_576, 16_777_216).unwrap();
        let restored_worker = StorageWorker::open(restored, 1_048_576, 16_777_216, 2).unwrap();
        assert_eq!(
            restored_worker
                .get("user/01".into())
                .unwrap()
                .recv()
                .unwrap()
                .unwrap(),
            Some(b"before".to_vec())
        );
        drop(restored_worker);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn restore_rejects_a_corrupt_backup() {
        let path = path();
        prepare_path(&path).unwrap();
        let backup = path.parent().unwrap().join("corrupt.redb");
        fs::write(&backup, b"not-redb").unwrap();
        let restored = path.parent().unwrap().join("restored.redb");
        assert!(matches!(
            restore_stopped_database(&backup, &restored, 1_048_576, 16_777_216),
            Err(StorageError::Database(_))
        ));
        assert!(!restored.exists());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
