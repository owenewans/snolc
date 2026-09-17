use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};

use redb::{Database, Durability, ReadableDatabase, TableDefinition};
use thiserror::Error;

const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("policy");
pub type ReadReply = Receiver<Result<Option<Vec<u8>>, StorageError>>;
pub type WriteReply = Receiver<Result<(), StorageError>>;

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
    Stop,
}

pub struct StorageWorker {
    sender: SyncSender<Command>,
    worker: Option<JoinHandle<()>>,
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
        let mut builder = Database::builder();
        builder.set_cache_size(cache_bytes);
        let database = builder.create(&path).map_err(database_error)?;
        set_file_permissions(&path)?;
        {
            let mut transaction = database.begin_write().map_err(transaction_error)?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(|error| StorageError::Database(error.to_string()))?;
            transaction.open_table(KV).map_err(table_error)?;
            transaction.commit().map_err(commit_error)?;
        }
        let (sender, receiver) = sync_channel(queue_capacity);
        let worker = thread::Builder::new()
            .name("snolc-policy-storage".into())
            .spawn(move || run(database, path, max_database_bytes, receiver))?;
        Ok(Self {
            sender,
            worker: Some(worker),
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

    fn send(&self, command: Command) -> Result<(), StorageError> {
        self.sender.try_send(command).map_err(|error| match error {
            TrySendError::Full(_) => StorageError::QueueFull,
            TrySendError::Disconnected(_) => StorageError::Stopped,
        })
    }
}

impl Drop for StorageWorker {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run(database: Database, path: PathBuf, max_bytes: u64, receiver: Receiver<Command>) {
    while let Ok(command) = receiver.recv() {
        match command {
            Command::Get { key, response } => {
                let _ = response.send(get_value(&database, &key));
            }
            Command::Put {
                key,
                value,
                response,
            } => {
                let result = enforce_size(&path, max_bytes, key.len(), value.len())
                    .and_then(|()| put_value(&database, &key, &value));
                let _ = response.send(result);
            }
            Command::Delete { key, response } => {
                let _ = response.send(delete_value(&database, &key));
            }
            Command::Stop => break,
        }
    }
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

fn enforce_size(path: &Path, max_bytes: u64, key: usize, value: usize) -> Result<(), StorageError> {
    let current = fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let addition = u64::try_from(key.saturating_add(value)).map_err(|_| StorageError::Limit)?;
    if current.saturating_add(addition) > max_bytes {
        return Err(StorageError::Limit);
    }
    Ok(())
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

fn prepare_path(path: &Path) -> Result<(), StorageError> {
    let directory = path.parent().ok_or(StorageError::Invalid)?;
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

fn set_file_permissions(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

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
}
