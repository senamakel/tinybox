//! Tests that drive a real Docker daemon.
//!
//! Gated behind `TINYBOX_LIVE_DOCKER=1` and named `live_*` so an ordinary
//! `cargo test` skips them: they need a daemon, pull images, and are far slower
//! than the unit suite. Everything about argument construction is covered
//! without a daemon in `src/sandbox/test.rs`; what is here is what only a real
//! daemon can answer.
//!
//! The isolation tests assert **negatively** — that the box *cannot* see the
//! host — because a positive assertion would pass just as happily against a
//! sandbox that confines nothing.
//!
//! Run them with:
//!
//! ```sh
//! TINYBOX_LIVE_DOCKER=1 cargo test -p tinybox-docker --test live_docker
//! ```
//!
//! CI also sets `TINYBOX_REQUIRE_LIVE_DOCKER=1`; in that mode the focused
//! connectivity test fails if the opt-in gate was not enabled.

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use tinybox_core::{
    BoxSpec, Error, ExecRequest, Host as _, HostRef, MemoryStore, NetworkPolicy, Placement,
    PortMapping, Result, Sandbox, SandboxRef, WorkspaceSource,
};
use tinybox_docker::{DockerSandbox, EgressResolver, NativeLinuxDockerEgressController};
use tinybox_host::LocalHost;

/// The image every live test uses. Small, and it ships a shell.
const IMAGE: &str = "alpine:3";

/// Whether the live suite should run at all.
fn enabled() -> bool {
    std::env::var_os("TINYBOX_LIVE_DOCKER").is_some()
}

/// Enforce the CI opt-in contract and report whether live Docker tests should run.
fn live_docker_enabled() -> Result<bool> {
    let enabled = enabled();
    if std::env::var_os("TINYBOX_REQUIRE_LIVE_DOCKER").is_some() && !enabled {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "run required live network test",
            message: "TINYBOX_REQUIRE_LIVE_DOCKER is set but TINYBOX_LIVE_DOCKER is not enabled"
                .to_owned(),
        });
    }
    Ok(enabled)
}

/// Return the default bridge gateway used as the controlled listener address.
fn docker_bridge_gateway() -> Result<Ipv4Addr> {
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            "bridge",
            "--format",
            "{{(index .IPAM.Config 0).Gateway}}",
        ])
        .output()
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "inspect the default bridge gateway",
            message: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "inspect the default bridge gateway",
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "parse the default bridge gateway",
            message: format!(
                "{}: {error}",
                String::from_utf8_lossy(&output.stdout).trim()
            ),
        })
}

/// Accept one connection before `deadline`, polling a nonblocking listener.
fn accept_before(listener: &TcpListener, deadline: Instant) -> std::io::Result<TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timed out waiting for the Docker network probe",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Connect to a published guest port and collect its response before timeout.
fn exchange_before(address: SocketAddr, deadline: Instant) -> Result<Vec<u8>> {
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .map_err(|error| Error::io("set published-port read timeout", &error))?;
                stream
                    .write_all(b"published-port probe\n")
                    .map_err(|error| Error::io("request published-port response", &error))?;
                let mut response = Vec::new();
                let mut chunk = [0; 1024];
                loop {
                    let read = match stream.read(&mut chunk) {
                        Ok(read) => read,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) && Instant::now() < deadline =>
                        {
                            continue;
                        }
                        Err(error)
                            if error.kind() == std::io::ErrorKind::ConnectionReset
                                && Instant::now() < deadline =>
                        {
                            break;
                        }
                        Err(error) => {
                            return Err(Error::io("read published-port response", &error));
                        }
                    };
                    if read == 0 {
                        return Ok(response);
                    }
                    response.extend_from_slice(&chunk[..read]);
                    if response
                        .windows(b"published-ok\n".len())
                        .any(|window| window == b"published-ok\n")
                    {
                        return Ok(response);
                    }
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(Error::Backend {
                        sandbox: "docker".to_owned(),
                        operation: "connect to published container port",
                        message: error.to_string(),
                    });
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(Error::io("connect to published container port", &error)),
        }
    }
}

/// Build the bounded HTTP request the container uses to probe the listener.
fn http_probe_command(address: SocketAddr) -> String {
    format!("wget -q -T 3 -O - http://{address}/probe")
}

/// Confirm the host can connect before using this listener to test container policy.
fn prove_host_can_reach_listener(listener: &TcpListener, address: SocketAddr) -> Result<()> {
    let host = TcpStream::connect_timeout(&address, Duration::from_secs(3)).map_err(|error| {
        Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "connect the host positive control",
            message: error.to_string(),
        }
    })?;
    let _accepted_host =
        accept_before(listener, Instant::now() + Duration::from_secs(3)).map_err(|error| {
            Error::Backend {
                sandbox: "docker".to_owned(),
                operation: "accept the host positive control",
                message: error.to_string(),
            }
        })?;
    drop(host);
    Ok(())
}

/// A sandbox in its own namespace.
///
/// Every test allocates `box-0` from a fresh store, so without a per-test
/// namespace they would all fight over one container name on the daemon — which
/// is exactly the collision the namespace exists to prevent.
fn sandbox(namespace: &str) -> Result<DockerSandbox> {
    DockerSandbox::with_namespace(
        Arc::new(LocalHost::new()),
        Arc::new(MemoryStore::new()),
        namespace,
    )
}

fn spec_from(source: WorkspaceSource) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("docker")?),
        source,
    ))
}

fn spec() -> Result<BoxSpec> {
    spec_from(WorkspaceSource::OciImage(IMAGE.to_owned()))
}

/// Run `argv` in a box and return its trimmed standard output.
async fn output_of(
    sandbox: &DockerSandbox,
    id: &tinybox_core::BoxId,
    argv: &[&str],
) -> Result<String> {
    let output = sandbox.exec(id, &ExecRequest::new(argv.to_vec())).await?;
    Ok(output.stdout_lossy().trim().to_owned())
}

#[tokio::test]
async fn live_a_box_runs_a_command_in_a_real_container() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-abraciarc")?;
    let info = sandbox.create(&spec()?).await?;

    let result = output_of(&sandbox, &info.id, &["echo", "from-the-container"]).await;

    sandbox.destroy(&info.id).await?;
    assert_eq!(result?, "from-the-container");
    Ok(())
}

#[tokio::test]
async fn live_the_box_cannot_see_host_processes() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-tbcshp")?;
    let info = sandbox.create(&spec()?).await?;

    let result = output_of(
        &sandbox,
        &info.id,
        &["sh", "-c", "ls /proc | grep -c '^[0-9]*$'"],
    )
    .await;

    sandbox.destroy(&info.id).await?;

    // The host has hundreds of processes. A PID-namespaced container sees only
    // its own handful, so a large count here means the isolation is not real.
    let visible: usize = result?.parse().unwrap_or(usize::MAX);
    assert!(
        visible < 20,
        "expected a private process table, saw {visible} processes"
    );
    Ok(())
}

#[tokio::test]
async fn live_the_box_has_its_own_root_filesystem() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-tbhiorf")?;
    let info = sandbox.create(&spec()?).await?;

    // A file that exists on the host checkout must not be visible inside.
    let result = output_of(
        &sandbox,
        &info.id,
        &[
            "sh",
            "-c",
            "test -e /etc/alpine-release && echo alpine; test -e /home/enamakel && echo LEAKED",
        ],
    )
    .await;

    sandbox.destroy(&info.id).await?;
    let seen = result?;
    assert!(seen.contains("alpine"));
    assert!(!seen.contains("LEAKED"), "the host filesystem was visible");
    Ok(())
}

#[tokio::test]
async fn live_a_denied_network_really_is_denied() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-adnrid")?;
    let info = sandbox.create(&spec()?).await?;

    // With `--network none` the container has only a loopback interface.
    let result = output_of(&sandbox, &info.id, &["sh", "-c", "ip -o link | wc -l"]).await;

    sandbox.destroy(&info.id).await?;
    let interfaces: usize = result?.parse().unwrap_or(usize::MAX);
    assert_eq!(interfaces, 1, "expected loopback only");
    Ok(())
}

#[tokio::test]
async fn live_egress_is_available_when_the_policy_allows_it() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-eiawtpai")?;
    let info = sandbox
        .create(&spec()?.with_network(NetworkPolicy::Egress))
        .await?;

    let result = output_of(&sandbox, &info.id, &["sh", "-c", "ip -o link | wc -l"]).await;

    sandbox.destroy(&info.id).await?;
    let interfaces: usize = result?.parse().unwrap_or(0);
    assert!(interfaces > 1, "expected more than loopback");
    Ok(())
}

/// Checks host, Egress, and default-Denied connectivity to a controlled listener.
#[tokio::test]
async fn live_network_policy_controls_host_listener_connectivity() -> Result<()> {
    if !live_docker_enabled()? {
        return Ok(());
    }

    let gateway = docker_bridge_gateway()?;
    let listener = TcpListener::bind((gateway, 0)).map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "bind the controlled bridge-gateway listener",
        message: error.to_string(),
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "configure the controlled listener",
            message: error.to_string(),
        })?;
    let address = listener.local_addr().map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "read the controlled listener address",
        message: error.to_string(),
    })?;

    // Prove the local endpoint is reachable before it is used as a sandbox
    // policy probe.
    prove_host_can_reach_listener(&listener, address)?;

    let egress_sandbox = sandbox("ns-docker-network-egress")?;
    let egress_info = egress_sandbox
        .create(&spec()?.with_network(NetworkPolicy::Egress))
        .await?;
    let egress_listener = listener.try_clone().map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "clone the controlled listener",
        message: error.to_string(),
    })?;
    let egress_server = thread::spawn(move || -> std::io::Result<()> {
        let mut stream = accept_before(&egress_listener, Instant::now() + Duration::from_secs(5))?;
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request)?;
        stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\ndocker-ok",
        )
    });
    let egress_result = egress_sandbox
        .exec(
            &egress_info.id,
            &ExecRequest::new(["sh", "-c", &http_probe_command(address)]),
        )
        .await;
    let egress_server_result = egress_server.join().map_err(|_| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "join the Egress listener",
        message: "listener thread panicked".to_owned(),
    })?;
    let egress_destroy = egress_sandbox.destroy(&egress_info.id).await;
    let egress = egress_result?;
    egress_destroy?;
    assert_eq!(
        egress.exit_code,
        0,
        "Egress container could not reach the listener: {}",
        egress.stderr_lossy()
    );
    egress_server_result.map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "accept the Egress container connection",
        message: error.to_string(),
    })?;
    assert_eq!(egress.stdout_lossy().trim(), "docker-ok");

    let denied_sandbox = sandbox("ns-docker-network-denied")?;
    let denied_info = denied_sandbox.create(&spec()?).await?;
    let denied = denied_sandbox
        .exec(
            &denied_info.id,
            &ExecRequest::new(["sh", "-c", &http_probe_command(address)]),
        )
        .await;
    let no_denied_connection = matches!(
        accept_before(&listener, Instant::now() + Duration::from_millis(250)),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut
    );
    let denied_destroy = denied_sandbox.destroy(&denied_info.id).await;
    let denied = denied?;
    denied_destroy?;
    assert_ne!(
        denied.exit_code, 0,
        "default-Denied container unexpectedly fetched the local response"
    );
    assert!(
        no_denied_connection,
        "default-Denied container established a connection to the controlled listener"
    );
    live_allowlist_pins_destinations_and_blocks_other_raw_tcp().await?;
    live_allowlist_dns_rebinding_stays_pinned().await?;
    Ok(())
}

#[derive(Debug)]
struct FixedResolver(Vec<std::net::IpAddr>);

impl EgressResolver for FixedResolver {
    fn resolve(&self, _hostname: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
        Ok(self.0.clone())
    }
}

#[derive(Debug)]
struct LoopbackDnsResolver {
    server: SocketAddr,
    calls: Arc<AtomicUsize>,
}

impl EgressResolver for LoopbackDnsResolver {
    fn resolve(&self, hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let id = 0x5200_u16.wrapping_add(u16::try_from(call).unwrap_or(u16::MAX));
        let query = dns_a_query(hostname, id)?;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.send_to(&query, self.server)?;
        let mut response = [0_u8; 512];
        let (length, _) = socket.recv_from(&mut response)?;
        dns_a_answers(&response[..length], id)
    }
}

#[derive(Debug)]
struct RebindingDnsServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    queries: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}

impl RebindingDnsServer {
    fn start(first: Ipv4Addr, second: Ipv4Addr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let queries = Arc::new(AtomicUsize::new(0));
        let worker_queries = queries.clone();
        let worker = thread::spawn(move || {
            let mut request = [0_u8; 512];
            while !worker_stop.load(Ordering::SeqCst) {
                match socket.recv_from(&mut request) {
                    Ok((length, peer)) => {
                        let answer = if worker_queries.fetch_add(1, Ordering::SeqCst) == 0 {
                            first
                        } else {
                            second
                        };
                        if let Some(response) = dns_a_response(&request[..length], answer) {
                            let _ = socket.send_to(&response, peer);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            address,
            stop,
            queries,
            worker: Some(worker),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn query_count(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

impl Drop for RebindingDnsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn dns_a_query(hostname: &str, id: u16) -> std::io::Result<Vec<u8>> {
    let mut query = vec![0_u8; 12];
    query[..2].copy_from_slice(&id.to_be_bytes());
    query[2..4].copy_from_slice(&0x0100_u16.to_be_bytes()); // recursion desired
    query[4..6].copy_from_slice(&1_u16.to_be_bytes());
    for label in hostname.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DNS fixture hostname contains an invalid label",
            ));
        }
        query.push(
            u8::try_from(label.len())
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?,
        );
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes()); // A
    query.extend_from_slice(&1_u16.to_be_bytes()); // IN
    Ok(query)
}

fn dns_a_response(query: &[u8], answer: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 || read_dns_u16(query, 4)? != 1 {
        return None;
    }
    let mut question_end = 12;
    skip_dns_name(query, &mut question_end)?;
    question_end = question_end.checked_add(4)?;
    if question_end > query.len() {
        return None;
    }

    let mut response = query[..question_end].to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes()); // response, recursion available
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response[8..10].copy_from_slice(&0_u16.to_be_bytes());
    response[10..12].copy_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c]); // compressed owner name points to the question
    response.extend_from_slice(&1_u16.to_be_bytes()); // A
    response.extend_from_slice(&1_u16.to_be_bytes()); // IN
    response.extend_from_slice(&30_u32.to_be_bytes()); // TTL
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&answer.octets());
    Some(response)
}

fn dns_a_answers(response: &[u8], id: u16) -> std::io::Result<Vec<IpAddr>> {
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "controlled DNS server returned a malformed response",
        )
    };
    if response.len() < 12
        || read_dns_u16(response, 0) != Some(id)
        || !matches!(read_dns_u16(response, 2), Some(flags) if flags & 0x800f == 0x8000)
    {
        return Err(invalid());
    }

    let question_count = read_dns_u16(response, 4).ok_or_else(invalid)?;
    let answer_count = read_dns_u16(response, 6).ok_or_else(invalid)?;
    let mut cursor = 12;
    for _ in 0..question_count {
        skip_dns_name(response, &mut cursor).ok_or_else(invalid)?;
        cursor = cursor.checked_add(4).ok_or_else(invalid)?;
        if cursor > response.len() {
            return Err(invalid());
        }
    }

    let mut addresses = Vec::new();
    for _ in 0..answer_count {
        skip_dns_name(response, &mut cursor).ok_or_else(invalid)?;
        let record_type = read_dns_u16(response, cursor).ok_or_else(invalid)?;
        let class = read_dns_u16(response, cursor + 2).ok_or_else(invalid)?;
        let data_length = usize::from(read_dns_u16(response, cursor + 8).ok_or_else(invalid)?);
        cursor = cursor.checked_add(10).ok_or_else(invalid)?;
        let data_end = cursor.checked_add(data_length).ok_or_else(invalid)?;
        if data_end > response.len() {
            return Err(invalid());
        }
        if record_type == 1 && class == 1 && data_length == 4 {
            let bytes: [u8; 4] = response[cursor..data_end]
                .try_into()
                .map_err(|_| invalid())?;
            addresses.push(IpAddr::V4(Ipv4Addr::from(bytes)));
        }
        cursor = data_end;
    }
    if addresses.is_empty() {
        return Err(invalid());
    }
    Ok(addresses)
}

fn read_dns_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset.checked_add(1)?)?,
    ]))
}

fn skip_dns_name(packet: &[u8], cursor: &mut usize) -> Option<()> {
    loop {
        let length = *packet.get(*cursor)?;
        if length & 0xc0 == 0xc0 {
            *cursor = cursor.checked_add(2)?;
            return (*cursor <= packet.len()).then_some(());
        }
        if length & 0xc0 != 0 {
            return None;
        }
        *cursor = cursor.checked_add(1)?;
        if length == 0 {
            return Some(());
        }
        *cursor = cursor.checked_add(usize::from(length))?;
        if *cursor > packet.len() {
            return None;
        }
    }
}

fn docker_command(arguments: &[&str]) -> Result<String> {
    let output = Command::new("docker")
        .args(arguments)
        .output()
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "run the controlled egress listener",
            message: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "run the controlled egress listener",
            message: format!(
                "docker {arguments:?} exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn docker_container_ipv4(name: &str) -> Result<Ipv4Addr> {
    docker_command(&[
        "inspect",
        "--format",
        "{{(index .NetworkSettings.Networks \"bridge\").IPAddress}}",
        name,
    ])?
    .parse::<Ipv4Addr>()
    .map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "read the controlled listener address",
        message: error.to_string(),
    })
}

fn ipv6_address_inspect_template(network: &str) -> String {
    format!("{{{{(index .NetworkSettings.Networks \"{network}\").GlobalIPv6Address}}}}")
}

fn allowlist_probe_ports() -> tinybox_core::EgressAllowlist {
    tinybox_core::EgressAllowlist::new(["listener.test"], [18373, 18376])
}

const TARGET_LISTENER_SCRIPT: &str = "(while true; do nc -l -p 18373 >/dev/null; echo hit >> /tmp/allowed; done) & (while true; do nc -l -p 18374 >/dev/null; echo hit >> /tmp/blocked; done) & (while true; do nc -l -p 18376 >/dev/null; echo hit >> /tmp/allowed-v6; done) & (while true; do nc -u -l -p 53 >/dev/null; echo hit >> /tmp/dns; done) & wait";
fn ipv6_listener_probe(address: Ipv6Addr) -> String {
    format!(
        "unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; nc -z -w 3 {address} 18376"
    )
}

#[test]
fn live_allowlist_covers_both_listener_probe_ports() {
    let allowlist = allowlist_probe_ports();
    assert!(allowlist.ports.contains(&18373));
    assert!(allowlist.ports.contains(&18376));
}

#[test]
fn alpine_busybox_nc_uses_literal_ipv6_without_unsupported_flag() {
    let address = Ipv6Addr::new(0xfd42, 0, 0, 0, 0, 0, 0, 0x1234);
    let probe = ipv6_listener_probe(address);
    assert!(TARGET_LISTENER_SCRIPT.contains("nc -l -p 18376"));
    assert!(!TARGET_LISTENER_SCRIPT.contains("nc -6"));
    assert!(probe.contains("nc -z -w 3 fd42::1234 18376"));
    assert!(!probe.contains("listener.test"));
    assert!(!probe.contains("nc -6"));
}

#[test]
fn ipv6_address_inspect_template_quotes_the_network_name() {
    assert_eq!(
        ipv6_address_inspect_template("controlled-v6"),
        r#"{{(index .NetworkSettings.Networks "controlled-v6").GlobalIPv6Address}}"#
    );
}

#[test]
fn loopback_dns_resolver_observes_first_and_rebound_addresses() -> std::io::Result<()> {
    let first = Ipv4Addr::new(192, 0, 2, 10);
    let second = Ipv4Addr::new(192, 0, 2, 20);
    let server = RebindingDnsServer::start(first, second)?;
    let resolver = LoopbackDnsResolver {
        server: server.address(),
        calls: Arc::new(AtomicUsize::new(0)),
    };

    assert_eq!(resolver.resolve("rebinding.test")?, [IpAddr::V4(first)]);
    assert_eq!(resolver.resolve("rebinding.test")?, [IpAddr::V4(second)]);
    assert_eq!(server.query_count(), 2);
    Ok(())
}

/// A disposable Linux Engine proof for the native firewall controller.
///
/// Both listeners run in a separate, test-owned bridge container, so this
/// exercises raw TCP from the sandbox without opening a path to the Docker
/// host or relying on a public service.
// Keep setup, all three probes, assertions, and cleanup together so cleanup
// runs on every assertion path in the live integration test.
#[allow(clippy::too_many_lines)]
async fn live_allowlist_pins_destinations_and_blocks_other_raw_tcp() -> Result<()> {
    const ALLOWED_PORT: &str = "18373";
    const BLOCKED_PORT: &str = "18374";

    if !live_docker_enabled()? {
        return Ok(());
    }

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let target_name = format!("tinybox-egress-target-{}", &suffix[..12]);
    let target_network = format!("tinybox-egress-v6-{}", &suffix[..12]);
    let target_subnet = format!("fd42:{}:5678::/64", &suffix[..4]);
    let gateway = docker_bridge_gateway()?;
    let host_listener = TcpListener::bind((gateway, 0)).map_err(|error| Error::Backend {
        sandbox: "docker".to_owned(),
        operation: "bind the host-gateway negative-control listener",
        message: error.to_string(),
    })?;
    host_listener
        .set_nonblocking(true)
        .map_err(|error| Error::io("configure host-gateway listener", &error))?;
    let host_address = host_listener
        .local_addr()
        .map_err(|error| Error::io("read host-gateway listener address", &error))?;
    let image = docker_command(&[
        "run",
        "-d",
        "--name",
        &target_name,
        IMAGE,
        "sh",
        "-c",
        TARGET_LISTENER_SCRIPT,
    ]);
    let _ = image?;
    if let Err(error) = docker_command(&[
        "network",
        "create",
        "--driver",
        "bridge",
        "--ipv6",
        "--subnet",
        &target_subnet,
        &target_network,
    ]) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &target_name])
            .status();
        return Err(error);
    }
    let result = async {
        docker_command(&["network", "connect", &target_network, &target_name])?;
        let ipv4 = docker_command(&[
            "inspect",
            "--format",
            "{{(index .NetworkSettings.Networks \"bridge\").IPAddress}}",
            &target_name,
        ])?
        .parse::<std::net::IpAddr>()
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "read the controlled listener address",
            message: error.to_string(),
        })?;
        let ipv6 = docker_command(&[
            "inspect",
            "--format",
            &ipv6_address_inspect_template(&target_network),
            &target_name,
        ])?
        .parse::<Ipv6Addr>()
        .map_err(|error| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "read the controlled IPv6 listener address",
            message: error.to_string(),
        })?;

        let resolver: Arc<dyn EgressResolver> =
            Arc::new(FixedResolver(vec![ipv4, std::net::IpAddr::V6(ipv6)]));
        let namespace = format!("ns-egress-{}", &suffix[..8]);
        let sandbox = sandbox(&namespace)?
            .with_egress_controller(Arc::new(NativeLinuxDockerEgressController::new(resolver)));
        let allowlist = allowlist_probe_ports();
        let info = sandbox
            .create(
                &spec()?
                    .with_network(NetworkPolicy::Allowlist(allowlist))
                    .with_port(PortMapping::dynamic(18375)),
            )
            .await?;

        let probes = async {
        let container = format!("tinybox-{namespace}-{}", info.id);
        docker_command(&[
            "exec",
            "-d",
            &container,
                "sh",
                "-c",
                "while true; do printf 'published-ok\\n' | nc -l -p 18375; done",
        ])?;
        let published_port = sandbox
            .published_ports(&info.id)
            .await?
            .into_iter()
            .find(|mapping| mapping.guest == 18375)
            .and_then(|mapping| mapping.host)
            .ok_or_else(|| Error::Backend {
                sandbox: "docker".to_owned(),
                operation: "inspect published container port",
                message: "Docker did not assign a host port".to_owned(),
            })?;
        let published_response = exchange_before(
            SocketAddr::from((Ipv4Addr::LOCALHOST, published_port)),
            Instant::now() + Duration::from_secs(5),
        )?;

        let allowed = sandbox
            .exec(
                &info.id,
                &ExecRequest::new([
                    "sh",
                    "-c",
                    &format!("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; nc -z -w 3 listener.test {ALLOWED_PORT}"),
                ]),
            )
            .await;
        let allowed_v6 = sandbox
            .exec(
                &info.id,
                &ExecRequest::new([
                    "sh",
                    "-c",
                    &ipv6_listener_probe(ipv6),
                ]),
            )
            .await;
        let blocked = sandbox
            .exec(
                &info.id,
                &ExecRequest::new([
                    "sh",
                    "-c",
                    &format!("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; nc -z -w 2 {ipv4} {BLOCKED_PORT}"),
                ]),
            )
            .await;
        let host_gateway = sandbox
            .exec(
                &info.id,
                &ExecRequest::new([
                    "sh",
                    "-c",
                    &format!("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; nc -z -w 2 {} {}", host_address.ip(), host_address.port()),
                ]),
            )
            .await;
        let dns_blocked = sandbox
            .exec(
                &info.id,
                &ExecRequest::new([
                    "sh",
                    "-c",
                    "unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; nslookup -timeout=1 -retry=1 unlisted-name.test >/dev/null 2>&1",
                ]),
            )
            .await;
        let direct_dns = sandbox
            .exec(
                &info.id,
                &ExecRequest::new([
                    "sh",
                    "-c",
                    &format!("printf probe | nc -u -w 1 {ipv4} 53 || true"),
                ]),
            )
            .await;
        let host_listener_untouched = matches!(
            accept_before(&host_listener, Instant::now() + Duration::from_millis(250)),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut
        );
        let allowed_hits =
            docker_command(&["exec", &target_name, "sh", "-c", "test -s /tmp/allowed"]);
        let allowed_v6_hits = docker_command(&[
            "exec",
            &target_name,
            "sh",
            "-c",
            "test -s /tmp/allowed-v6",
        ]);
        let blocked_hits = Command::new("docker")
            .args(["exec", &target_name, "sh", "-c", "test ! -s /tmp/blocked"])
            .status()
            .map_err(|error| Error::io("check forbidden listener", &error));
        let dns_hits = Command::new("docker")
            .args(["exec", &target_name, "sh", "-c", "test ! -s /tmp/dns"])
            .status()
            .map_err(|error| Error::io("check forbidden DNS listener", &error));

        let allowed = allowed?;
        let allowed_v6 = allowed_v6?;
        if allowed.exit_code != 0 || allowed_v6.exit_code != 0 {
            return Err(Error::Backend {
                sandbox: "docker".to_owned(),
                operation: "connect the allowlisted controlled listener",
                message: format!(
                    "allowed v4 exit={} stderr={:?}; allowed v6 exit={} stderr={:?}",
                    allowed.exit_code,
                    allowed.stderr_lossy(),
                    allowed_v6.exit_code,
                    allowed_v6.stderr_lossy()
                ),
            });
        }
        let blocked = blocked?;
        let host_gateway = host_gateway?;
        let dns_blocked = dns_blocked?;
        direct_dns?;
        allowed_hits?;
        allowed_v6_hits?;
        let blocked_hits = blocked_hits?;
        let dns_hits = dns_hits?;
        if allowed.exit_code != 0
            || allowed_v6.exit_code != 0
            || blocked.exit_code == 0
            || host_gateway.exit_code == 0
            || dns_blocked.exit_code == 0
            || !published_response
                .windows(b"published-ok\n".len())
                .any(|window| window == b"published-ok\n")
            || !blocked_hits.success()
            || !dns_hits.success()
            || !host_listener_untouched
        {
            return Err(Error::Backend {
                sandbox: "docker".to_owned(),
                operation: "verify native egress allowlist",
                message: format!(
                    "allowed v4 exit={}, allowed v6 exit={}, blocked exit={}, host-gateway exit={}, unlisted DNS lookup exit={}, published response={published_response:?}, forbidden TCP hit={}, forbidden DNS hit={}, host listener touched={}",
                    allowed.exit_code,
                    allowed_v6.exit_code,
                    blocked.exit_code,
                    host_gateway.exit_code,
                    dns_blocked.exit_code,
                    !blocked_hits.success(),
                    !dns_hits.success(),
                    !host_listener_untouched
                ),
            });
        }
        Ok(())
        }
        .await;
        let destroy = sandbox.destroy(&info.id).await;
        probes?;
        destroy?;
        Ok(())
    }
    .await;
    let cleanup = Command::new("docker")
        .args(["rm", "-f", &target_name])
        .status()
        .map_err(|error| Error::io("remove controlled listener", &error));
    let network_cleanup = Command::new("docker")
        .args(["network", "rm", &target_network])
        .status()
        .map_err(|error| Error::io("remove controlled IPv6 listener network", &error));
    result?;
    let cleanup = cleanup?;
    let network_cleanup = network_cleanup?;
    if !cleanup.success() || !network_cleanup.success() {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "remove controlled listeners",
            message: "docker rm or docker network rm returned a failure status".to_owned(),
        });
    }
    Ok(())
}

/// A loopback DNS server rebinds after prepare; the container stays pinned to
/// the first answer and cannot connect to the later answer's listener.
#[allow(clippy::too_many_lines)]
async fn live_allowlist_dns_rebinding_stays_pinned() -> Result<()> {
    const ALLOWED_PORT: &str = "18373";

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let first_target = format!("tinybox-rebind-first-{}", &suffix[..12]);
    let second_target = format!("tinybox-rebind-second-{}", &suffix[..12]);
    for name in [&first_target, &second_target] {
        docker_command(&[
            "run",
            "-d",
            "--name",
            name,
            IMAGE,
            "sh",
            "-c",
            TARGET_LISTENER_SCRIPT,
        ])?;
    }

    let result = async {
        let first_address = docker_container_ipv4(&first_target)?;
        let second_address = docker_container_ipv4(&second_target)?;
        let dns = RebindingDnsServer::start(first_address, second_address).map_err(|error| {
            Error::Backend {
                sandbox: "docker".to_owned(),
                operation: "start controlled loopback DNS server",
                message: error.to_string(),
            }
        })?;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(LoopbackDnsResolver {
            server: dns.address(),
            calls: calls.clone(),
        });
        let namespace = format!("ns-rebind-{}", &suffix[..8]);
        let sandbox = sandbox(&namespace)?.with_egress_controller(Arc::new(
            NativeLinuxDockerEgressController::new(resolver.clone()),
        ));
        let allowlist = tinybox_core::EgressAllowlist::new(["rebinding.test"], [18373]);
        let info = sandbox
            .create(&spec()?.with_network(NetworkPolicy::Allowlist(allowlist)))
            .await?;

        let probes = async {
            if calls.load(Ordering::SeqCst) != 1 || dns.query_count() != 1 {
                return Err(Error::Backend {
                    sandbox: "docker".to_owned(),
                    operation: "verify initial DNS pinning lookup",
                    message: format!(
                        "controller made {} resolver calls and DNS server saw {} queries",
                        calls.load(Ordering::SeqCst),
                        dns.query_count()
                    ),
                });
            }

            // Demonstrate that the controlled DNS source has changed its
            // answer after the controller prepared the box.
            let rebound_address = resolver
                .resolve("rebinding.test")
                .map_err(|error| Error::Backend {
                    sandbox: "docker".to_owned(),
                    operation: "query rebound DNS answer",
                    message: error.to_string(),
                })?;
            if rebound_address != [IpAddr::V4(second_address)]
                || dns.query_count() != 2
                || calls.load(Ordering::SeqCst) != 2
            {
                return Err(Error::Backend {
                    sandbox: "docker".to_owned(),
                    operation: "verify controlled DNS rebinding",
                    message: format!("unexpected rebound answers: {rebound_address:?}"),
                });
            }

            let host_mapping = output_of(
                &sandbox,
                &info.id,
                &[
                    "sh",
                    "-c",
                    "awk '$2 == \"rebinding.test\" { print $1 }' /etc/hosts",
                ],
            )
            .await?;
            if host_mapping != first_address.to_string() {
                return Err(Error::Backend {
                    sandbox: "docker".to_owned(),
                    operation: "verify pinned container host mapping",
                    message: format!(
                        "rebinding.test mapped to {host_mapping}, expected {first_address}"
                    ),
                });
            }

            let allowed = sandbox
                .exec(
                    &info.id,
                    &ExecRequest::new([
                        "sh",
                        "-c",
                        &format!("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; nc -z -w 3 rebinding.test {ALLOWED_PORT}"),
                    ]),
                )
                .await?;
            let rebound = sandbox
                .exec(
                    &info.id,
                    &ExecRequest::new([
                        "sh",
                        "-c",
                        &format!("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; nc -z -w 2 {second_address} {ALLOWED_PORT}"),
                    ]),
                )
                .await?;
            docker_command(&[
                "exec",
                &first_target,
                "sh",
                "-c",
                "test -s /tmp/allowed",
            ])?;
            docker_command(&[
                "exec",
                &second_target,
                "sh",
                "-c",
                "test ! -s /tmp/allowed",
            ])?;
            if allowed.exit_code != 0 || rebound.exit_code == 0 {
                return Err(Error::Backend {
                    sandbox: "docker".to_owned(),
                    operation: "verify DNS rebinding egress remains pinned",
                    message: format!(
                        "hostname exit={}, direct rebound address exit={}",
                        allowed.exit_code, rebound.exit_code
                    ),
                });
            }
            Ok(())
        }
        .await;
        let destroy = sandbox.destroy(&info.id).await;
        probes?;
        destroy?;
        Ok(())
    }
    .await;

    let first_cleanup = Command::new("docker")
        .args(["rm", "-f", &first_target])
        .status()
        .map_err(|error| Error::io("remove first rebinding listener", &error));
    let second_cleanup = Command::new("docker")
        .args(["rm", "-f", &second_target])
        .status()
        .map_err(|error| Error::io("remove second rebinding listener", &error));
    result?;
    let first_cleanup = first_cleanup?;
    let second_cleanup = second_cleanup?;
    if !first_cleanup.success() || !second_cleanup.success() {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "remove DNS rebinding listeners",
            message: "docker rm returned a failure status".to_owned(),
        });
    }
    Ok(())
}

#[tokio::test]
async fn live_a_memory_limit_is_actually_enforced() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-amliae")?;
    let spec = spec()?.with_resources(tinybox_core::Resources {
        memory_bytes: 64 * 1024 * 1024,
        ..tinybox_core::Resources::DEFAULT
    });
    let info = sandbox.create(&spec).await?;

    // Reading `memory.max` would only prove the cgroup was *configured*, and an
    // earlier version of this test did exactly that. So this allocates for
    // real. The allocation is anonymous memory held by the shell rather than a
    // file write: a write to `/tmp` measures disk in Docker and memory under
    // namespaces, which made an earlier probe silently test nothing at all.
    let over = output_of(
        &sandbox,
        &info.id,
        &["sh", "-c", "x=$(yes a | head -c 100000000); echo SURVIVED"],
    )
    .await;

    // ...and a modest allocation under the same cap still works, so this is
    // measuring a limit rather than a broken container.
    let under = output_of(
        &sandbox,
        &info.id,
        &["sh", "-c", "x=$(yes a | head -c 8000000); echo ok"],
    )
    .await;

    sandbox.destroy(&info.id).await?;
    assert!(
        !over?.contains("SURVIVED"),
        "a 100 MiB allocation was not stopped by a 64 MiB cap"
    );
    assert_eq!(under?, "ok");
    Ok(())
}

#[tokio::test]
async fn live_a_local_directory_is_visible_inside_the_box() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = tempfile::tempdir().map_err(|error| Error::io("tempdir", &error))?;
    std::fs::write(dir.path().join("note.txt"), "mounted\n")
        .map_err(|error| Error::io("write", &error))?;

    let sandbox = sandbox("ns-localdir")?;
    let info = sandbox
        .create(&spec_from(WorkspaceSource::LocalDir(dir.path().into()))?)
        .await?;

    // The bind mount is also the working directory, so a bare filename resolves.
    let result = output_of(&sandbox, &info.id, &["cat", "note.txt"]).await;

    sandbox.destroy(&info.id).await?;
    assert_eq!(result?, "mounted");
    Ok(())
}

#[tokio::test]
async fn live_a_snapshot_captures_a_write_and_a_fork_starts_from_it() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-ascawaafsfi")?;
    let parent = sandbox.create(&spec()?).await?;

    // Write into the parent, then capture it.
    sandbox
        .exec(
            &parent.id,
            &ExecRequest::new(["sh", "-c", "echo captured > /marker"]),
        )
        .await?;
    let snapshot = sandbox.snapshot(&parent.id).await?;

    let forked = sandbox.fork(&snapshot, &spec()?).await?;

    // The fork inherits the parent's filesystem...
    let inherited = output_of(&sandbox, &forked.id, &["cat", "/marker"]).await;

    // ...and writes in the fork do not reach back into the parent.
    sandbox
        .exec(
            &forked.id,
            &ExecRequest::new(["sh", "-c", "echo fork-only > /fork-marker"]),
        )
        .await?;
    let parent_sees_fork = output_of(
        &sandbox,
        &parent.id,
        &[
            "sh",
            "-c",
            "test -e /fork-marker && echo LEAKED || echo isolated",
        ],
    )
    .await;

    sandbox.destroy(&forked.id).await?;
    sandbox.destroy(&parent.id).await?;

    assert_eq!(inherited?, "captured");
    assert_eq!(parent_sees_fork?, "isolated");
    Ok(())
}

#[tokio::test]
async fn live_a_destroyed_box_leaves_no_container_behind() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-adblncb")?;
    let info = sandbox.create(&spec()?).await?;
    let name = tinybox_docker::container_name(sandbox.namespace(), &info.id);

    sandbox.destroy(&info.id).await?;

    let listed = LocalHost::new()
        .run(&ExecRequest::new([
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--filter",
            &format!("name=^{name}$"),
        ]))
        .await?;

    assert!(
        listed.stdout_lossy().trim().is_empty(),
        "container {name} survived destroy"
    );
    Ok(())
}

#[tokio::test]
async fn live_a_missing_image_is_reported_with_dockers_diagnostic() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-amiirwdd")?;

    let outcome = sandbox
        .create(&spec_from(WorkspaceSource::OciImage(
            "tinybox.invalid/no-such-image:0".to_owned(),
        ))?)
        .await;

    assert!(matches!(
        outcome,
        Err(Error::Backend {
            operation: "create the container",
            ..
        })
    ));
    Ok(())
}
