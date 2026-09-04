use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::routing::{Action, RuleSet};
use crate::tunnel::{ClientSession, ProtectedStream, Target, TargetHost};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct Connector {
    sessions: watch::Receiver<Option<ClientSession>>,
    routing: Option<Arc<RuleSet>>,
}

pub enum Outbound {
    Direct(TcpStream),
    Proxy(ProtectedStream),
}

impl Connector {
    pub fn new(
        sessions: watch::Receiver<Option<ClientSession>>,
        routing: Option<Arc<RuleSet>>,
    ) -> Self {
        Self { sessions, routing }
    }

    pub async fn connect(&self, target: &Target) -> Result<Outbound> {
        let action = match &self.routing {
            Some(routing) => routing.decide(target.domain_name(), target.ip_address())?,
            None => Action::Proxy,
        };
        match action {
            Action::Direct => {
                let stream = timeout(CONNECT_TIMEOUT, connect_direct(target))
                    .await
                    .map_err(|_| Error::Carrier("direct connection timed out".to_owned()))??;
                Ok(Outbound::Direct(stream))
            }
            Action::Proxy => {
                let session = self
                    .sessions
                    .borrow()
                    .clone()
                    .ok_or_else(|| Error::Carrier("no active server connection".to_owned()))?;
                Ok(Outbound::Proxy(session.open_tcp(target).await?))
            }
        }
    }
}

impl Outbound {
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        match self {
            Self::Direct(stream) => {
                use tokio::io::AsyncWriteExt;
                stream.write_all(payload).await?;
                stream.flush().await?;
                Ok(())
            }
            Self::Proxy(stream) => stream.send(payload).await,
        }
    }

    pub async fn relay<L>(self, mut local: L) -> Result<()>
    where
        L: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            Self::Direct(mut remote) => {
                tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
                Ok(())
            }
            Self::Proxy(remote) => remote.relay(local).await,
        }
    }
}

async fn connect_direct(target: &Target) -> Result<TcpStream> {
    let stream = match &target.host {
        TargetHost::Ip(ip) => TcpStream::connect((*ip, target.port)).await?,
        TargetHost::Domain(domain) => TcpStream::connect((domain.as_str(), target.port)).await?,
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::routing::Rule;

    #[tokio::test]
    async fn direct_rule_bypasses_an_absent_proxy_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let byte = stream.read_u8().await.unwrap();
            stream.write_u8(byte + 1).await.unwrap();
        });
        let mut rules = RuleSet {
            rules: vec![
                Rule::Ip {
                    value: "127.0.0.0/8".parse().unwrap(),
                    action: Action::Direct,
                },
                Rule::Any {
                    action: Action::Proxy,
                },
            ],
        };
        rules.normalize_and_validate().unwrap();
        let (_sessions_tx, sessions_rx) = watch::channel(None);
        let connector = Connector::new(sessions_rx, Some(Arc::new(rules)));
        let target = Target::ip(address.ip(), address.port()).unwrap();
        let outbound = connector.connect(&target).await.unwrap();
        let (mut application, relay_side) = tokio::io::duplex(64);
        let relay = tokio::spawn(outbound.relay(relay_side));
        application.write_u8(7).await.unwrap();
        assert_eq!(application.read_u8().await.unwrap(), 8);
        drop(application);
        timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server.await.unwrap();
    }
}
