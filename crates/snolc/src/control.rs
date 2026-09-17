use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use futures::channel::oneshot;
use thiserror::Error;

use crate::EngineError;

const REQUEST_HEADER_BYTES: usize = 8;
const RESPONSE_HEADER_BYTES: usize = 5;
const MAX_INSTANCE_BYTES: usize = 128;

pub(crate) struct UnixControlServer {
    listener: UnixListener,
    path: PathBuf,
    max_request_bytes: usize,
    max_connections: usize,
    next_connection: u64,
    connections: HashMap<u64, Connection>,
}

pub(crate) struct LocalRequest {
    pub(crate) connection: u64,
    pub(crate) instance: String,
    pub(crate) request: Vec<u8>,
}

struct Connection {
    stream: UnixStream,
    input: Vec<u8>,
    state: ConnectionState,
}

enum ConnectionState {
    Reading,
    Dispatched,
    Waiting(oneshot::Receiver<Result<Vec<u8>, EngineError>>),
    Writing { frame: Vec<u8>, offset: usize },
}

impl UnixControlServer {
    pub(crate) fn bind(
        path: &Path,
        max_request_bytes: usize,
        max_connections: usize,
    ) -> Result<Self, ControlError> {
        let parent = path.parent().ok_or(ControlError::Path)?;
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                return Err(ControlError::Path);
            }
            fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            max_request_bytes,
            max_connections,
            next_connection: 1,
            connections: HashMap::new(),
        })
    }

    pub(crate) fn poll(&mut self) -> Vec<LocalRequest> {
        self.accept();
        let mut requests = Vec::new();
        let mut closed = Vec::new();
        for (id, connection) in &mut self.connections {
            match connection.poll(self.max_request_bytes) {
                Ok(Some((instance, request))) => {
                    requests.push(LocalRequest {
                        connection: *id,
                        instance,
                        request,
                    });
                }
                Ok(None) => {}
                Err(_) => closed.push(*id),
            }
            if connection.finished() {
                closed.push(*id);
            }
        }
        closed.sort_unstable();
        closed.dedup();
        for id in closed {
            self.connections.remove(&id);
        }
        requests
    }

    pub(crate) fn wait_for(
        &mut self,
        connection: u64,
        receiver: oneshot::Receiver<Result<Vec<u8>, EngineError>>,
    ) {
        if let Some(connection) = self.connections.get_mut(&connection)
            && matches!(connection.state, ConnectionState::Dispatched)
        {
            connection.state = ConnectionState::Waiting(receiver);
        }
    }

    pub(crate) fn reject(&mut self, connection: u64, error: &EngineError) {
        if let Some(connection) = self.connections.get_mut(&connection) {
            connection.response(Err(error.to_string()), self.max_request_bytes);
        }
    }

    fn accept(&mut self) {
        while self.connections.len() < self.max_connections {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if !peer_is_owner(&stream) || stream.set_nonblocking(true).is_err() {
                continue;
            }
            let id = self.next_connection;
            let Some(next) = id.checked_add(1) else {
                continue;
            };
            self.next_connection = next;
            self.connections.insert(
                id,
                Connection {
                    stream,
                    input: Vec::new(),
                    state: ConnectionState::Reading,
                },
            );
        }
    }
}

impl Drop for UnixControlServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Connection {
    fn poll(
        &mut self,
        max_request_bytes: usize,
    ) -> Result<Option<(String, Vec<u8>)>, ControlError> {
        match &mut self.state {
            ConnectionState::Reading => self.read_request(max_request_bytes),
            ConnectionState::Dispatched => Ok(None),
            ConnectionState::Waiting(receiver) => {
                match receiver.try_recv() {
                    Ok(Some(Ok(response))) => self.response(Ok(response), max_request_bytes),
                    Ok(Some(Err(error))) => {
                        self.response(Err(error.to_string()), max_request_bytes)
                    }
                    Ok(None) => {}
                    Err(_) => {
                        self.response(Err("control response canceled".into()), max_request_bytes)
                    }
                }
                Ok(None)
            }
            ConnectionState::Writing { frame, offset } => {
                match self.stream.write(&frame[*offset..]) {
                    Ok(0) => return Err(ControlError::Closed),
                    Ok(written) => *offset += written,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
                Ok(None)
            }
        }
    }

    fn read_request(
        &mut self,
        max_request_bytes: usize,
    ) -> Result<Option<(String, Vec<u8>)>, ControlError> {
        let maximum = REQUEST_HEADER_BYTES
            .checked_add(MAX_INSTANCE_BYTES)
            .and_then(|size| size.checked_add(max_request_bytes))
            .ok_or(ControlError::Frame)?;
        let mut buffer = [0; 4096];
        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err(ControlError::Closed),
                Ok(read) => {
                    if self.input.len().saturating_add(read) > maximum {
                        return Err(ControlError::Frame);
                    }
                    self.input.extend_from_slice(&buffer[..read]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        let Some((instance_length, request_length)) = request_lengths(&self.input) else {
            return Ok(None);
        };
        if instance_length == 0
            || instance_length > MAX_INSTANCE_BYTES
            || request_length > max_request_bytes
        {
            return Err(ControlError::Frame);
        }
        let total = REQUEST_HEADER_BYTES
            .checked_add(instance_length)
            .and_then(|size| size.checked_add(request_length))
            .ok_or(ControlError::Frame)?;
        if self.input.len() < total {
            return Ok(None);
        }
        if self.input.len() != total {
            return Err(ControlError::Frame);
        }
        let instance = std::str::from_utf8(
            &self.input[REQUEST_HEADER_BYTES..REQUEST_HEADER_BYTES + instance_length],
        )
        .map_err(|_| ControlError::Frame)?
        .to_owned();
        let request = self.input[REQUEST_HEADER_BYTES + instance_length..].to_vec();
        self.input.clear();
        self.state = ConnectionState::Dispatched;
        Ok(Some((instance, request)))
    }

    fn response(&mut self, response: Result<Vec<u8>, String>, max_response_bytes: usize) {
        let (status, payload) = match response {
            Ok(mut payload) => {
                payload.truncate(max_response_bytes);
                (0, payload)
            }
            Err(mut error) => {
                let mut end = error.len().min(max_response_bytes);
                while !error.is_char_boundary(end) {
                    end -= 1;
                }
                error.truncate(end);
                (1, error.into_bytes())
            }
        };
        let mut frame = Vec::with_capacity(RESPONSE_HEADER_BYTES + payload.len());
        frame.push(status);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        self.state = ConnectionState::Writing { frame, offset: 0 };
    }

    fn finished(&self) -> bool {
        matches!(
            &self.state,
            ConnectionState::Writing { frame, offset } if *offset == frame.len()
        )
    }
}

fn request_lengths(input: &[u8]) -> Option<(usize, usize)> {
    let header: [u8; REQUEST_HEADER_BYTES] = input.get(..REQUEST_HEADER_BYTES)?.try_into().ok()?;
    Some((
        u32::from_be_bytes(header[..4].try_into().ok()?) as usize,
        u32::from_be_bytes(header[4..].try_into().ok()?) as usize,
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_is_owner(stream: &UnixStream) -> bool {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    result == 0
        && length as usize == size_of::<libc::ucred>()
        && credentials.uid == unsafe { libc::geteuid() }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peer_is_owner(_stream: &UnixStream) -> bool {
    false
}

pub fn request(
    path: &Path,
    instance: &str,
    request: &[u8],
    max_response_bytes: usize,
) -> Result<Vec<u8>, ControlError> {
    if instance.is_empty()
        || instance.len() > MAX_INSTANCE_BYTES
        || instance.len() > u32::MAX as usize
        || request.len() > u32::MAX as usize
    {
        return Err(ControlError::Frame);
    }
    let mut stream = UnixStream::connect(path)?;
    stream.write_all(&(instance.len() as u32).to_be_bytes())?;
    stream.write_all(&(request.len() as u32).to_be_bytes())?;
    stream.write_all(instance.as_bytes())?;
    stream.write_all(request)?;
    let mut header = [0; RESPONSE_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    let length =
        u32::from_be_bytes(header[1..].try_into().map_err(|_| ControlError::Frame)?) as usize;
    if length > max_response_bytes {
        return Err(ControlError::Frame);
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload)?;
    if header[0] == 0 {
        Ok(payload)
    } else if header[0] == 1 {
        Err(ControlError::Remote(
            String::from_utf8(payload).map_err(|_| ControlError::Frame)?,
        ))
    } else {
        Err(ControlError::Frame)
    }
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("control socket I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("control socket path is invalid")]
    Path,
    #[error("control frame is invalid")]
    Frame,
    #[error("control connection closed")]
    Closed,
    #[error("control request failed: {0}")]
    Remote(String),
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn bounded_server_round_trips_one_request() {
        let root = std::env::temp_dir().join(format!(
            "snolc-control-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = root.join("control.sock");
        let mut server = UnixControlServer::bind(&path, 1024, 1).unwrap();
        let client_path = path.clone();
        let client = std::thread::spawn(move || request(&client_path, "policy", b"status", 1024));
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut sent = false;
        while !client.is_finished() && Instant::now() < deadline {
            for request in server.poll() {
                assert_eq!(request.instance, "policy");
                assert_eq!(request.request, b"status");
                let (sender, receiver) = oneshot::channel();
                server.wait_for(request.connection, receiver);
                sender.send(Ok(b"ok".to_vec())).unwrap();
                sent = true;
            }
            std::thread::yield_now();
        }
        assert!(sent);
        assert_eq!(client.join().unwrap().unwrap(), b"ok");
        drop(server);
        assert!(!path.exists());
        fs::remove_dir(root).unwrap();
    }
}
