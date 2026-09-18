use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use thiserror::Error;

const TRUNCATED: &str = "… truncated\n";

pub struct FileLogger {
    queue: Arc<ArrayQueue<Vec<u8>>>,
    lost: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    max_record_bytes: usize,
}

impl FileLogger {
    pub fn start(
        path: PathBuf,
        limit_bytes: u64,
        queue_bytes: usize,
        max_record_bytes: usize,
        flush_interval: Duration,
        error_sink: impl Fn(String) + Send + 'static,
    ) -> Result<Self, LogError> {
        if limit_bytes == 0
            || queue_bytes == 0
            || max_record_bytes == 0
            || queue_bytes < max_record_bytes
            || max_record_bytes as u64 > limit_bytes
            || flush_interval.is_zero()
        {
            return Err(LogError::Invalid);
        }
        prepare_path(&path)?;
        let capacity = queue_bytes / max_record_bytes;
        let queue = Arc::new(ArrayQueue::new(capacity));
        let lost = Arc::new(AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_queue = Arc::clone(&queue);
        let worker_stopping = Arc::clone(&stopping);
        let worker = thread::Builder::new()
            .name("snolc-log".into())
            .spawn(move || {
                run_worker(
                    path,
                    limit_bytes,
                    worker_queue,
                    worker_stopping,
                    flush_interval,
                    error_sink,
                )
            })?;
        Ok(Self {
            queue,
            lost,
            stopping,
            worker: Some(worker),
            max_record_bytes,
        })
    }

    pub fn write(&self, record: &str) {
        let record = truncate_record(record, self.max_record_bytes);
        enqueue(&self.queue, &self.lost, record);
        if let Some(worker) = &self.worker {
            worker.thread().unpark();
        }
    }

    pub fn lost_records(&self) -> usize {
        self.lost.load(Ordering::Relaxed)
    }
}

impl Drop for FileLogger {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

fn run_worker(
    path: PathBuf,
    limit: u64,
    queue: Arc<ArrayQueue<Vec<u8>>>,
    stopping: Arc<AtomicBool>,
    interval: Duration,
    error_sink: impl Fn(String),
) {
    loop {
        let mut wrote = false;
        while let Some(record) = queue.pop() {
            if let Err(error) = append_record(&path, limit, &record) {
                error_sink(error.to_string());
            }
            wrote = true;
        }
        if stopping.load(Ordering::Acquire) && queue.is_empty() {
            break;
        }
        if !wrote {
            thread::park_timeout(interval);
        }
    }
}

fn enqueue(queue: &ArrayQueue<Vec<u8>>, lost: &AtomicUsize, record: Vec<u8>) {
    loop {
        match queue.push(record.clone()) {
            Ok(()) => break,
            Err(_) => {
                if queue.pop().is_some() {
                    lost.fetch_add(1, Ordering::Relaxed);
                } else {
                    thread::yield_now();
                }
            }
        }
    }
}

fn append_record(path: &Path, limit: u64, record: &[u8]) -> Result<(), LogError> {
    let length = fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let record_length = u64::try_from(record.len()).map_err(|_| LogError::Invalid)?;
    if length.saturating_add(record_length) <= limit {
        let mut file = append_file(path)?;
        file.write_all(record)?;
        file.sync_data()?;
        return Ok(());
    }
    compact(path, limit, record)
}

fn compact(path: &Path, limit: u64, record: &[u8]) -> Result<(), LogError> {
    let temporary = temporary_path(path)?;
    let mut source = File::open(path)?;
    let source_length = source.metadata()?.len();
    let record_length = u64::try_from(record.len()).map_err(|_| LogError::Invalid)?;
    let keep = (limit.saturating_mul(3) / 4).min(limit.saturating_sub(record_length));
    let start = source_length.saturating_sub(keep);
    source.seek(SeekFrom::Start(start))?;
    if start != 0 {
        let mut byte = [0; 1];
        loop {
            if source.read(&mut byte)? == 0 || byte[0] == b'\n' {
                break;
            }
        }
    }
    let temporary_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    set_private_permissions(&temporary)?;
    let result = (|| {
        let mut reader = BufReader::new(source.take(keep));
        let mut writer = BufWriter::new(temporary_file);
        io::copy(&mut reader, &mut writer)?;
        writer.write_all(record)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        fs::rename(&temporary, path)?;
        set_private_permissions(path)?;
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(Into::into)
}

fn truncate_record(record: &str, limit: usize) -> Vec<u8> {
    let needs_newline = !record.ends_with('\n');
    let full_length = record.len().saturating_add(usize::from(needs_newline));
    if full_length <= limit {
        let mut output = record.as_bytes().to_vec();
        if needs_newline {
            output.push(b'\n');
        }
        return output;
    }
    if limit <= TRUNCATED.len() {
        return b"truncated\n"[..limit.min(10)].to_vec();
    }
    let target = limit - TRUNCATED.len();
    let mut boundary = target.min(record.len());
    while !record.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut output = record.as_bytes()[..boundary].to_vec();
    output.extend_from_slice(TRUNCATED.as_bytes());
    output
}

fn prepare_path(path: &Path) -> Result<(), LogError> {
    let directory = path.parent().ok_or(LogError::Invalid)?;
    fs::create_dir_all(directory)?;
    if !path.exists() {
        append_file(path)?;
    }
    set_private_permissions(path)?;
    Ok(())
}

fn append_file(path: &Path) -> Result<File, io::Error> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn temporary_path(path: &Path) -> Result<PathBuf, LogError> {
    let name = path.file_name().ok_or(LogError::Invalid)?.to_string_lossy();
    Ok(path.with_file_name(format!(".{name}.compact-{}", std::process::id())))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), io::Error> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum LogError {
    #[error("logger limits are invalid")]
    Invalid,
    #[error("logger I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "snolc-log-{}-{}.log",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn startup_appends_and_compaction_keeps_complete_records() {
        let path = path();
        fs::write(&path, b"old-one\nold-two\n").unwrap();
        append_record(&path, 24, b"new-three\n").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with("new-three\n"));
        assert!(contents.len() <= 24);
        assert!(!contents.starts_with("ld-"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn truncates_on_utf8_boundary() {
        let record = truncate_record("ёжик-ёжик-ёжик", 16);
        assert!(std::str::from_utf8(&record).is_ok());
        assert_eq!(record.len(), 16);
        assert!(std::str::from_utf8(&record).unwrap().ends_with(TRUNCATED));
    }

    #[test]
    fn queue_discards_oldest_records() {
        let queue = ArrayQueue::new(1);
        let lost = AtomicUsize::new(0);
        enqueue(&queue, &lost, b"first\n".to_vec());
        enqueue(&queue, &lost, b"second\n".to_vec());
        assert_eq!(lost.load(Ordering::Relaxed), 1);
        assert_eq!(queue.pop().unwrap(), b"second\n");
    }
}
