//! Datagram ownership and deadlines. Definitions and parsing stay in `browser`.
use super::{Encoding, Instance, Message, Problem, Reply, Request, read_reply, request};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{UdpSocket, lookup_host},
    time::{Instant, timeout_at},
};

#[derive(Clone, Debug)]
pub struct Options {
    pub port: u16,
    pub timeout_ms: u64,
    pub encoding: Encoding,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            port: super::PORT,
            timeout_ms: super::TIMEOUT_MS,
            encoding: Encoding::Ascii,
        }
    }
}

/// Request/target/cause and raw reply are inspectable, without automatically
/// printing arbitrary server bytes. Broadcast discards malformed replies.
#[derive(Debug)]
pub struct BrowserError {
    pub message: Message,
    pub instance: Option<String>,
    pub host: String,
    pub port: u16,
    pub problem: Problem,
    pub reply: Option<Vec<u8>>,
}
impl fmt::Display for BrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message.name())?;
        if let Some(instance) = &self.instance {
            write!(f, " for {instance:?}")?;
        }
        write!(f, " to {}:{}: {}", self.host, self.port, self.problem)
    }
}
impl std::error::Error for BrowserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.problem)
    }
}
fn error(
    host: &str,
    options: &Options,
    asked: Request<'_>,
    problem: Problem,
    reply: Option<Vec<u8>>,
) -> BrowserError {
    BrowserError {
        message: asked.message(),
        instance: asked.instance().map(str::to_owned),
        host: host.into(),
        port: options.port,
        problem,
        reply,
    }
}
fn deadline(options: &Options) -> Result<Instant, Problem> {
    Instant::now()
        .checked_add(Duration::from_millis(options.timeout_ms))
        .ok_or(Problem::InvalidTimeout)
}
async fn ask(host: &str, asked: Request<'_>, options: &Options) -> Result<Reply, BrowserError> {
    deadline(options).map_err(|p| error(host, options, asked, p, None))?; // refuse invalid options before sending
    let bytes =
        request(asked, options.encoding).map_err(|p| error(host, options, asked, p, None))?;
    let io = async {
        let remote = lookup_host((host, options.port))
            .await?
            .next()
            .ok_or_else(|| std::io::Error::other("host has no UDP addresses"))?;
        let local = if remote.is_ipv4() {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(remote).await?;
        socket.send(&bytes).await?;
        Ok::<_, std::io::Error>((socket, remote.ip()))
    };
    let (socket, address) = io
        .await
        .map_err(|e| error(host, options, asked, Problem::Io(e), None))?;
    let end = deadline(options).map_err(|p| error(host, options, asked, p, None))?;
    let mut bytes = vec![0; 65535];
    let n = timeout_at(end, socket.recv(&mut bytes))
        .await
        .map_err(|_| error(host, options, asked, Problem::Timeout, None))?
        .map_err(|e| error(host, options, asked, Problem::Io(e), None))?;
    bytes.truncate(n);
    let mut reply = read_reply(&bytes, asked.message(), options.encoding)
        .map_err(|p| error(host, options, asked, p, Some(bytes)))?;
    if let Reply::Instances(instances) = &mut reply {
        for instance in instances {
            instance.address = Some(address);
        }
    }
    Ok(reply)
}
pub async fn instance(host: &str, name: &str, options: &Options) -> Result<Instance, BrowserError> {
    let asked = Request::Instance(name);
    let Reply::Instances(mut found) = ask(host, asked, options).await? else {
        unreachable!()
    };
    if found.len() != 1 {
        return Err(error(
            host,
            options,
            asked,
            Problem::InstanceCount(found.len()),
            None,
        ));
    }
    Ok(found.remove(0))
}
pub async fn machine(host: &str, options: &Options) -> Result<Vec<Instance>, BrowserError> {
    let Reply::Instances(found) = ask(host, Request::Machine, options).await? else {
        unreachable!()
    };
    Ok(found)
}
pub async fn dac_port(host: &str, name: &str, options: &Options) -> Result<u16, BrowserError> {
    let Reply::DacPort(port) = ask(host, Request::Dac(name), options).await? else {
        unreachable!()
    };
    Ok(port)
}
/// IPv4 only, as in Python: MC-SQLR specifies no IPv6 multicast group. A caller
/// may use loopback for controlled tests instead of broadcasting on a network.
pub async fn broadcast(
    address: Ipv4Addr,
    options: &Options,
) -> Result<Vec<Instance>, BrowserError> {
    let host = address.to_string();
    let asked = Request::Broadcast;
    let end = deadline(options).map_err(|p| error(&host, options, asked, p, None))?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|e| error(&host, options, asked, Problem::Io(e), None))?;
    socket
        .set_broadcast(true)
        .map_err(|e| error(&host, options, asked, Problem::Io(e), None))?;
    socket
        .send_to(&[Message::Broadcast as u8], (address, options.port))
        .await
        .map_err(|e| error(&host, options, asked, Problem::Io(e), None))?;
    let mut bytes = vec![0; 65535];
    let mut found = Vec::new();
    while Instant::now() < end {
        let Ok(result) = timeout_at(end, socket.recv_from(&mut bytes)).await else {
            break;
        };
        let Ok((n, sender)) = result else {
            continue;
        };
        if let Ok(Reply::Instances(instances)) =
            read_reply(&bytes[..n], Message::Broadcast, options.encoding)
        {
            found.extend(instances.into_iter().map(|mut i| {
                i.address = Some(sender.ip());
                i
            }));
        }
    }
    Ok(found)
}
