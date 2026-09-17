use futures::channel::mpsc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Lifecycle {
    Configured = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
    Stopped = 4,
    Failed = 5,
}

impl Lifecycle {
    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Configured,
            1 => Self::Starting,
            2 => Self::Running,
            3 => Self::Stopping,
            4 => Self::Stopped,
            _ => Self::Failed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    Lifecycle(Lifecycle),
    Module { instance: String, payload: Vec<u8> },
    ModuleError { instance: String, message: String },
    Tunnel { name: String, state: &'static str },
    ResourceExhausted { resource: &'static str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub lifecycle: Lifecycle,
    pub sessions: usize,
    pub flows: usize,
    pub lost_events: usize,
}

pub type EventReceiver = mpsc::Receiver<Event>;
