//! Forwards DNS from VPN containers to resolvers in a chosen order.
//!
//! Queries arrive on one local port, UDP and TCP. A resolver that stays
//! silent or gives up hands the question to the next one in the order.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

/// AdGuard Home or Pi-hole, published on loopback
pub const LOOPBACK_RESOLVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

const NEAR_WAIT: Duration = Duration::from_millis(1500);
const FAR_WAIT: Duration = Duration::from_millis(2500);
/// How long a silent resolver waits at the back
const BENCHED_FOR: Duration = Duration::from_secs(30);
const TCP_IDLE: Duration = Duration::from_secs(30);
const MAX_IN_FLIGHT: usize = 256;
const MAX_DATAGRAM: usize = 65_535;

/// The resolvers in order, and which of them went silent
#[derive(Debug, Default)]
pub struct Resolvers {
    order: RwLock<Vec<SocketAddr>>,
    benched: Mutex<HashMap<SocketAddr, Instant>>,
    tally: Mutex<Tally>,
}

/// What happened to queries since the last report
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Tally {
    per_server: HashMap<SocketAddr, ServerTally>,
    unanswered: u32,
    dropped: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct ServerTally {
    answered: u32,
    silent: u32,
    gave_up: u32,
    slowest: Duration,
}

impl Tally {
    fn troubled(&self) -> bool {
        self.unanswered > 0 || self.dropped > 0 || self.per_server.values().any(|s| s.silent > 0 || s.gave_up > 0)
    }

    /// One log line: each resolver, then what got no answer
    pub fn line(&self) -> String {
        let mut servers: Vec<_> = self.per_server.iter().collect();
        servers.sort_by_key(|(server, _)| server.to_string());
        let mut parts: Vec<String> = servers
            .into_iter()
            .map(|(server, s)| {
                format!(
                    "{server}: {} answered, {} silent, {} failed, slowest {} ms",
                    s.answered,
                    s.silent,
                    s.gave_up,
                    s.slowest.as_millis()
                )
            })
            .collect();
        parts.push(format!("{} unanswered, {} dropped as too many", self.unanswered, self.dropped));
        parts.join("; ")
    }
}

impl Resolvers {
    pub fn new(order: Vec<SocketAddr>) -> Arc<Self> {
        Arc::new(Resolvers {
            order: RwLock::new(order),
            benched: Mutex::new(HashMap::new()),
            tally: Mutex::new(Tally::default()),
        })
    }

    /// The tally since the last call, if anything went wrong
    pub fn report(&self) -> Option<Tally> {
        let taken = std::mem::take(&mut *self.tally.lock().unwrap_or_else(|poison| poison.into_inner()));
        taken.troubled().then_some(taken)
    }

    fn count(&self, change: impl FnOnce(&mut Tally)) {
        change(&mut self.tally.lock().unwrap_or_else(|poison| poison.into_inner()));
    }

    fn count_server(&self, server: SocketAddr, change: impl FnOnce(&mut ServerTally)) {
        self.count(|tally| change(tally.per_server.entry(server).or_default()));
    }

    pub fn set(&self, order: Vec<SocketAddr>) {
        *self.order.write().unwrap_or_else(|poison| poison.into_inner()) = order;
    }

    pub fn order(&self) -> Vec<SocketAddr> {
        self.order.read().unwrap_or_else(|poison| poison.into_inner()).clone()
    }

    /// Whether it answered, or has not been tried lately
    pub fn reachable(&self, server: SocketAddr) -> bool {
        self.benched_until(server).is_none_or(|until| until <= Instant::now())
    }

    /// The order to try now: silent ones last
    pub fn plan(&self) -> Vec<SocketAddr> {
        let (mut ready, benched): (Vec<_>, Vec<_>) = self.order().into_iter().partition(|s| self.reachable(*s));
        ready.extend(benched);
        ready
    }

    fn benched_until(&self, server: SocketAddr) -> Option<Instant> {
        self.benched.lock().unwrap_or_else(|poison| poison.into_inner()).get(&server).copied()
    }

    fn heard(&self, server: SocketAddr) {
        self.benched.lock().unwrap_or_else(|poison| poison.into_inner()).remove(&server);
    }

    fn silent(&self, server: SocketAddr) {
        let mut benched = self.benched.lock().unwrap_or_else(|poison| poison.into_inner());
        benched.insert(server, Instant::now() + BENCHED_FOR);
    }
}

/// Containers, the tunnel and loopback only; never the internet
pub fn allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| allowed(IpAddr::V4(v4))),
    }
}

/// Private and loopback resolvers get less patience
fn wait_for(server: SocketAddr) -> Duration {
    if allowed(server.ip()) { NEAR_WAIT } else { FAR_WAIT }
}

/// One UDP question to one server
pub async fn ask_udp(server: SocketAddr, query: &[u8], wait: Duration) -> io::Result<Vec<u8>> {
    let local: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().expect("literal");
    let socket = UdpSocket::bind(local).await?;
    socket.connect(server).await?;
    socket.send(query).await?;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let len = tokio::time::timeout(wait, socket.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer"))??;
    buf.truncate(len);
    Ok(buf)
}

/// The first real answer, else the first failure
pub async fn answer(resolvers: &Resolvers, query: &[u8]) -> Option<Vec<u8>> {
    let mut failure = None;
    for server in resolvers.plan() {
        let started = Instant::now();
        match ask_udp(server, query, wait_for(server)).await {
            Ok(reply) => {
                resolvers.heard(server);
                let failed = gave_up(&reply);
                resolvers.count_server(server, |s| {
                    s.slowest = s.slowest.max(started.elapsed());
                    if failed { s.gave_up += 1 } else { s.answered += 1 }
                });
                if !failed {
                    return Some(reply);
                }
                failure.get_or_insert(reply);
            }
            Err(_) => {
                resolvers.silent(server);
                resolvers.count_server(server, |s| s.silent += 1);
            }
        }
    }
    resolvers.count(|tally| tally.unanswered += 1);
    failure
}

/// SERVFAIL or REFUSED: the resolver could not answer
pub fn gave_up(reply: &[u8]) -> bool {
    const SERVFAIL: u8 = 2;
    const REFUSED: u8 = 5;
    reply.len() < 4 || matches!(reply[3] & 0x0F, SERVFAIL | REFUSED)
}

/// Answers datagrams until the socket fails
pub async fn serve_udp(socket: Arc<UdpSocket>, resolvers: Arc<Resolvers>) {
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(got) => got,
            Err(err) => {
                tracing::warn!(%err, "the VPN DNS relay could not read");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !allowed(from.ip()) {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            resolvers.count(|tally| tally.dropped += 1);
            continue;
        };
        let query = buf[..len].to_vec();
        let socket = socket.clone();
        let resolvers = resolvers.clone();
        tokio::spawn(async move {
            if let Some(reply) = answer(&resolvers, &query).await {
                let _ = socket.send_to(&reply, from).await;
            }
            drop(permit);
        });
    }
}

/// Accepts DNS-over-TCP connections and pipes each one through
pub async fn serve_tcp(listener: TcpListener, resolvers: Arc<Resolvers>) {
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    loop {
        let Ok((client, from)) = listener.accept().await else { continue };
        if !allowed(from.ip()) {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
        let resolvers = resolvers.clone();
        tokio::spawn(async move {
            relay_tcp(client, &resolvers).await;
            drop(permit);
        });
    }
}

async fn relay_tcp(mut client: TcpStream, resolvers: &Resolvers) {
    let Some(mut server) = open_tcp(resolvers).await else { return };
    let piped = tokio::time::timeout(TCP_IDLE, pipe(&mut client, &mut server));
    let _ = piped.await;
    let _ = client.shutdown().await;
}

async fn open_tcp(resolvers: &Resolvers) -> Option<TcpStream> {
    for server in resolvers.plan() {
        if let Ok(Ok(stream)) = tokio::time::timeout(wait_for(server), TcpStream::connect(server)).await {
            resolvers.heard(server);
            return Some(stream);
        }
        resolvers.silent(server);
    }
    None
}

/// Length-prefixed messages, one answer per question
async fn pipe(client: &mut TcpStream, server: &mut TcpStream) -> io::Result<()> {
    loop {
        let Some(question) = read_framed(client).await? else { return Ok(()) };
        write_framed(server, &question).await?;
        let Some(reply) = read_framed(server).await? else { return Ok(()) };
        write_framed(client, &reply).await?;
    }
}

async fn read_framed(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await?;
    Ok(Some(body))
}

async fn write_framed(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    let len = u16::try_from(body.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too long"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(body).await
}

/// Both sockets on the relay port, every address
pub async fn bind(port: u16) -> io::Result<(Arc<UdpSocket>, TcpListener)> {
    let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let udp = UdpSocket::bind(any).await?;
    let tcp = TcpListener::bind(any).await?;
    Ok((Arc::new(udp), tcp))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver that answers every question with "A:" + question
    async fn fake_udp_resolver() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let mut reply = b"A:".to_vec();
                reply.extend_from_slice(&buf[..len]);
                let _ = socket.send_to(&reply, from).await;
            }
        });
        addr
    }

    /// A resolver that answers with the question and this RCODE
    async fn failing_udp_resolver(rcode: u8) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let mut reply = buf[..len].to_vec();
                reply[3] = 0x80 | rcode;
                let _ = socket.send_to(&reply, from).await;
            }
        });
        addr
    }

    /// A port nothing listens on
    async fn closed_udp_port() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.local_addr().unwrap()
    }

    async fn fake_tcp_resolver() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    while let Ok(Some(question)) = read_framed(&mut stream).await {
                        let mut reply = b"T:".to_vec();
                        reply.extend_from_slice(&question);
                        if write_framed(&mut stream, &reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn only_private_and_loopback_sources_are_served() {
        for ok in ["172.18.0.2", "192.168.1.5", "10.9.0.3", "10.8.0.1", "127.0.0.1", "::1", "::ffff:172.17.0.4"] {
            assert!(allowed(ok.parse().unwrap()), "{ok}");
        }
        for no in ["203.0.113.7", "198.51.100.1", "2001:db8::1", "::ffff:203.0.113.7", "100.64.0.1"] {
            assert!(!allowed(no.parse().unwrap()), "{no}");
        }
    }

    #[tokio::test]
    async fn a_query_is_answered_by_the_first_resolver() {
        let resolvers = Resolvers::new(vec![fake_udp_resolver().await, closed_udp_port().await]);
        assert_eq!(answer(&resolvers, b"q1").await.as_deref(), Some(&b"A:q1"[..]));
    }

    #[tokio::test]
    async fn a_silence_is_reported_and_the_report_resets() {
        let resolvers = Resolvers::new(vec![closed_udp_port().await, fake_udp_resolver().await]);
        assert!(answer(&resolvers, b"q3").await.is_some());
        let report = resolvers.report().expect("the silence is reported");
        assert!(report.line().contains("1 silent"));
        assert!(report.line().contains("0 unanswered"));
        assert_eq!(resolvers.report(), None, "taken once");
        assert!(answer(&resolvers, b"q3").await.is_some());
        assert_eq!(resolvers.report(), None, "answers alone are not news");
    }

    #[tokio::test]
    async fn a_silent_resolver_hands_over_to_the_next() {
        let silent = closed_udp_port().await;
        let resolvers = Resolvers::new(vec![silent, fake_udp_resolver().await]);
        assert_eq!(answer(&resolvers, b"q2").await.as_deref(), Some(&b"A:q2"[..]));
        assert!(!resolvers.reachable(silent));
    }

    #[tokio::test]
    async fn a_silent_resolver_waits_at_the_back() {
        let silent = closed_udp_port().await;
        let second = fake_udp_resolver().await;
        let resolvers = Resolvers::new(vec![silent, second]);
        resolvers.silent(silent);
        assert_eq!(resolvers.plan(), vec![second, silent]);
        resolvers.heard(silent);
        assert_eq!(resolvers.plan(), vec![silent, second]);
    }

    #[tokio::test]
    async fn a_resolver_that_gives_up_hands_over_to_the_next() {
        for rcode in [2, 5] {
            let resolvers = Resolvers::new(vec![failing_udp_resolver(rcode).await, fake_udp_resolver().await]);
            assert_eq!(answer(&resolvers, b"q3xx").await.as_deref(), Some(&b"A:q3xx"[..]), "rcode {rcode}");
        }
    }

    #[tokio::test]
    async fn the_third_resolver_answers_when_two_fail() {
        let resolvers = Resolvers::new(vec![
            failing_udp_resolver(2).await,
            closed_udp_port().await,
            fake_udp_resolver().await,
        ]);
        assert_eq!(answer(&resolvers, b"q6xx").await.as_deref(), Some(&b"A:q6xx"[..]));
    }

    #[tokio::test]
    async fn no_such_name_is_an_answer() {
        let resolvers = Resolvers::new(vec![failing_udp_resolver(3).await, fake_udp_resolver().await]);
        assert_eq!(answer(&resolvers, b"q4xx").await, Some(vec![b'q', b'4', b'x', 0x83]));
    }

    #[tokio::test]
    async fn the_failure_is_passed_on_when_nothing_else_answers() {
        let resolvers = Resolvers::new(vec![failing_udp_resolver(2).await, closed_udp_port().await]);
        assert_eq!(answer(&resolvers, b"q5xx").await, Some(vec![b'q', b'5', b'x', 0x82]));
    }

    #[tokio::test]
    async fn an_empty_order_answers_nothing() {
        assert_eq!(answer(&Resolvers::new(Vec::new()), b"q7xx").await, None);
    }

    #[tokio::test]
    async fn the_udp_relay_answers_a_client_end_to_end() {
        let resolvers = Resolvers::new(vec![fake_udp_resolver().await, closed_udp_port().await]);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = socket.local_addr().unwrap();
        tokio::spawn(serve_udp(socket, resolvers));
        let reply = ask_udp(relay, b"q3", Duration::from_secs(5)).await.unwrap();
        assert_eq!(reply, b"A:q3");
    }

    #[tokio::test]
    async fn the_tcp_relay_pipes_framed_questions_and_falls_back() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let resolvers = Resolvers::new(vec![closed, fake_tcp_resolver().await]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(listener, resolvers));
        let mut client = TcpStream::connect(relay).await.unwrap();
        for question in [&b"q4"[..], &b"q5"[..]] {
            write_framed(&mut client, question).await.unwrap();
            let reply = read_framed(&mut client).await.unwrap().unwrap();
            assert_eq!(reply, [&b"T:"[..], question].concat());
        }
    }
}
