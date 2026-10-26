use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use ciborium::value::Value;

use super::{fetch_challenge, fetch_eek, rkp_client, submit_csr, validate_endpoint};
use crate::cbor::{bytes, encode, int};

struct Server {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn start(status: u16, body: Vec<u8>) -> Self {
        let length = body.len();
        Self::start_with_length(status, body, length)
    }

    fn start_with_length(status: u16, body: Vec<u8>, length: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (recorded, stopping) = (requests.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                let Ok((mut socket, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket.set_nonblocking(false).unwrap();
                let path = read_request(&mut socket);
                recorded.lock().unwrap().push(path);
                write!(
                    socket,
                    "HTTP/1.1 {status} Test\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                if let Err(error) = socket.write_all(&body) {
                    assert!(matches!(
                        error.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                    ));
                }
            }
        });
        Self {
            origin,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

fn read_request(socket: &mut TcpStream) -> String {
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut data = Vec::new();
    let (end, header) = loop {
        let mut buffer = [0; 4096];
        let size = socket.read(&mut buffer).unwrap();
        assert!(size > 0);
        data.extend_from_slice(&buffer[..size]);
        if let Some(end) = data.windows(4).position(|part| part == b"\r\n\r\n") {
            break (end + 4, String::from_utf8(data[..end].to_vec()).unwrap());
        }
    };
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while data.len() < end + length {
        let mut buffer = [0; 4096];
        let size = socket.read(&mut buffer).unwrap();
        assert!(size > 0);
        data.extend_from_slice(&buffer[..size]);
    }
    header.lines().next().unwrap().to_string()
}

fn eek_response() -> Vec<u8> {
    let public_key = encode(&Value::Map(vec![
        (int(1), int(1)),
        (int(3), int(-25)),
        (int(-1), int(4)),
        (int(-2), bytes(vec![0x33; 32])),
    ]))
    .unwrap();
    encode(&Value::Array(vec![
        Value::Array(vec![Value::Array(vec![
            int(2),
            Value::Array(vec![Value::Array(vec![
                Value::Null,
                Value::Null,
                bytes(public_key),
            ])]),
        ])]),
        bytes(vec![7; 32]),
    ]))
    .unwrap()
}

const ENDPOINT_PATHS: [(&str, &str); 5] = [
    ("/v1/", "/v1"),
    ("", "/v1"),
    ("/", "/v1"),
    ("/v1", "/v1"),
    ("/custom/version/", "/custom/version"),
];

#[tokio::test]
async fn challenge_requests_normalize_endpoint_paths() {
    for (input, expected) in ENDPOINT_PATHS {
        let server = Server::start(200, eek_response());
        let endpoint = format!("{}{input}", server.origin);
        validate_endpoint(&endpoint).unwrap();
        let challenge = fetch_challenge(&rkp_client().unwrap(), "synthetic", &endpoint)
            .await
            .unwrap();
        assert_eq!(challenge, [7; 32]);
        assert_rpc_request(&server, &format!("{expected}:fetchEekChain"));
    }
}

#[tokio::test]
async fn eek_requests_normalize_endpoint_paths() {
    for (input, expected) in ENDPOINT_PATHS {
        let server = Server::start(200, eek_response());
        let response = fetch_eek(
            &rkp_client().unwrap(),
            "synthetic",
            &format!("{}{input}", server.origin),
            123,
            9,
        )
        .await
        .unwrap();
        assert_eq!(response.challenge, [7; 32]);
        assert_eq!(response.eek_public, [0x33; 32]);
        assert_rpc_request(&server, &format!("{expected}:fetchEekChain"));
    }
}

#[tokio::test]
async fn submission_requests_normalize_endpoint_paths() {
    for (input, expected) in ENDPOINT_PATHS {
        let body = encode(&Value::Array(vec![
            bytes(vec![1]),
            Value::Array(vec![bytes(vec![2])]),
        ]))
        .unwrap();
        let server = Server::start(200, body);
        let chains = submit_csr(
            &rkp_client().unwrap(),
            b"synthetic CSR",
            &format!("{}{input}", server.origin),
        )
        .await
        .unwrap();
        assert_eq!(chains, [vec![1, 2]]);
        assert_rpc_request(&server, &format!("{expected}:signCertificates"));
    }
}

#[tokio::test]
async fn every_rpc_rejects_unsafe_endpoints_before_sending() {
    for invalid in [
        "http://example.com/v1",
        "https://user@example.com/v1",
        "https://example.com/v1?secret=synthetic",
        "https://example.com/v1#synthetic",
    ] {
        assert_eq!(
            crate::error::code_of(&validate_endpoint(invalid).unwrap_err()),
            "invalid_endpoint"
        );
    }
    for action in 0..3 {
        for suffix in ["?secret=synthetic", "#synthetic"] {
            let server = Server::start(200, eek_response());
            let endpoint = format!("{}/v1{suffix}", server.origin);
            let client = rkp_client().unwrap();
            let error = match action {
                0 => fetch_challenge(&client, "synthetic", &endpoint)
                    .await
                    .map(|_| ()),
                1 => fetch_eek(&client, "synthetic", &endpoint, 42, 37)
                    .await
                    .map(|_| ()),
                _ => submit_csr(&client, b"synthetic CSR", &endpoint)
                    .await
                    .map(|_| ()),
            }
            .unwrap_err();
            assert_eq!(crate::error::code_of(&error), "invalid_endpoint");
            assert!(server.requests().is_empty());
        }
    }
}

async fn submission_error(body: Vec<u8>, expected_reason: &str) {
    let server = Server::start(200, body);
    assert_submission_error(&server, expected_reason).await;
}

async fn assert_submission_error(server: &Server, expected_reason: &str) -> anyhow::Error {
    let error = submit_csr(
        &rkp_client().unwrap(),
        b"synthetic CSR",
        &format!("{}/v1", server.origin),
    )
    .await
    .unwrap_err();
    assert_eq!(crate::error::code_of(&error), "submission_unknown");
    assert!(error.to_string().contains("do not retry automatically"));
    let diagnostics = format!("{error:#} {error:?}");
    assert!(diagnostics.contains(expected_reason), "{diagnostics}");
    assert!(!diagnostics.contains("synthetic-response-secret"));
    assert_rpc_request(server, "/v1:signCertificates");
    error
}

#[tokio::test]
async fn truncated_transport_body_after_successful_submission_has_unknown_outcome() {
    let body = b"synthetic-response-secret".to_vec();
    let length = body.len() + 1;
    let server = Server::start_with_length(200, body, length);
    let error = assert_submission_error(&server, "certificate submission result is unknown").await;
    assert!(!error.chain().any(|cause| matches!(
        cause.downcast_ref::<crate::error::RkpError>(),
        Some(crate::error::RkpError::InvalidRkpResponse(_))
    )));
}

#[tokio::test]
async fn oversized_transport_body_after_successful_submission_has_unknown_outcome() {
    let marker = b"synthetic-response-secret";
    let mut body = vec![b'x'; 1024 * 1024 + 1];
    body[..marker.len()].copy_from_slice(marker);
    let server = Server::start(200, body);
    assert_submission_error(&server, "response exceeds size limit").await;
}

#[tokio::test]
async fn truncated_cbor_after_successful_submission_has_unknown_outcome() {
    submission_error(vec![0x81], "truncated CBOR").await;
}

#[tokio::test]
async fn malformed_shapes_after_successful_submission_have_unknown_outcome() {
    for (value, expected_reason) in [
        (
            Value::Text("synthetic-response-secret".into()),
            "signCertificates response is not a CBOR array",
        ),
        (Value::Array(vec![]), "signCertificates response is empty"),
        (
            Value::Array(vec![bytes(vec![1])]),
            "missing certificate chain data",
        ),
        (
            Value::Array(vec![bytes(vec![1]), Value::Array(vec![])]),
            "no certificate chains",
        ),
    ] {
        submission_error(encode(&value).unwrap(), expected_reason).await;
    }
}

#[tokio::test]
async fn submission_parse_diagnostics_do_not_reflect_duplicate_cbor_text_keys() {
    let body = encode(&Value::Map(vec![
        (Value::Text("synthetic-response-secret".into()), int(1)),
        (Value::Text("synthetic-response-secret".into()), int(2)),
    ]))
    .unwrap();
    submission_error(body, "malformed CBOR").await;
}

#[tokio::test]
async fn explicit_http_rejection_retains_server_codes_without_body_or_retry() {
    for (status, expected) in [
        (403, "rkp_client_error"),
        (444, "device_not_registered"),
        (503, "rkp_server_error"),
    ] {
        let server = Server::start(status, b"synthetic-response-secret".to_vec());
        let error = submit_csr(
            &rkp_client().unwrap(),
            b"synthetic CSR",
            &format!("{}/v1", server.origin),
        )
        .await
        .unwrap_err();
        assert_eq!(crate::error::code_of(&error), expected);
        assert!(!format!("{error:#} {error:?}").contains("synthetic-response-secret"));
        assert_eq!(server.requests().len(), 1);
    }
}

fn assert_rpc_request(server: &Server, path: &str) {
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let target = requests[0]
        .strip_prefix("POST ")
        .unwrap()
        .strip_suffix(" HTTP/1.1")
        .unwrap();
    let url = reqwest::Url::parse(&format!("{}{target}", server.origin)).unwrap();
    assert_eq!(url.path(), path);
    let pairs: Vec<_> = url.query_pairs().collect();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "request_id");
}
