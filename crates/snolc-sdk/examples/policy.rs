mod support;

use std::io;
use std::task::{Context, Poll, Waker};

use snolc_sdk::{Module, MuxStream, Policy, Pump, StackSocket};
use support::MemoryIo;

struct Flow {
    stack: StackSocket<MemoryIo>,
    mux: MuxStream<MemoryIo>,
    upload: Pump,
    download: Pump,
}

struct ExamplePolicy {
    session: Option<MuxStream<MemoryIo>>,
    flow: Option<Flow>,
}

impl Module for ExamplePolicy {
    type Error = io::Error;

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let Some(flow) = &mut self.flow else {
            return Poll::Pending;
        };
        let _ = flow
            .upload
            .poll(context, &mut flow.stack.0, &mut flow.mux.0, 16_384)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let _ = flow
            .download
            .poll(context, &mut flow.mux.0, &mut flow.stack.0, 16_384)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Poll::Ready(Ok(()))
    }

    fn control(&mut self, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn shutdown(&mut self) -> Result<(), Self::Error> {
        self.flow = None;
        self.session = None;
        Ok(())
    }
}

impl Policy for ExamplePolicy {
    type Session = MuxStream<MemoryIo>;
    type Flow = (StackSocket<MemoryIo>, MuxStream<MemoryIo>);

    fn attach_session(&mut self, session: Self::Session) -> Result<u64, Self::Error> {
        self.session = Some(session);
        Ok(1)
    }

    fn admit_flow(
        &mut self,
        _context: &mut Context<'_>,
        session: u64,
        _metadata: &[u8],
    ) -> Poll<Result<(), Self::Error>> {
        if session == 1 && self.session.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()))
        }
    }

    fn attach_flow(&mut self, session: u64, flow: Self::Flow) -> Result<(), Self::Error> {
        if session != 1 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.flow = Some(Flow {
            stack: flow.0,
            mux: flow.1,
            upload: Pump::new(16_384).map_err(|error| io::Error::other(error.to_string()))?,
            download: Pump::new(16_384).map_err(|error| io::Error::other(error.to_string()))?,
        });
        Ok(())
    }
}

fn main() {
    let mut policy = ExamplePolicy {
        session: None,
        flow: None,
    };
    let session = policy
        .attach_session(MuxStream(MemoryIo::default()))
        .unwrap();
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        policy.admit_flow(&mut context, session, b"metadata"),
        Poll::Ready(Ok(()))
    ));
    policy
        .attach_flow(
            session,
            (
                StackSocket(MemoryIo::with_input(b"upload")),
                MuxStream(MemoryIo::with_input(b"download")),
            ),
        )
        .unwrap();
    assert!(matches!(policy.poll(&mut context), Poll::Ready(Ok(()))));
    let flow = policy.flow.as_ref().unwrap();
    assert_eq!(flow.mux.0.output(), b"upload");
    assert_eq!(flow.stack.0.output(), b"download");
}
