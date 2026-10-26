use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use ciborium::value::Value;
use reqwest::{Client, Response, Url, redirect::Policy};

use crate::{
    cbor::{encode, int, text},
    error::RkpError,
};

const MAX_RESPONSE: usize = 1024 * 1024;

pub fn validate_endpoint(value: &str) -> Result<()> {
    endpoint_url(value).map(|_| ())
}

fn endpoint_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).map_err(|_| RkpError::InvalidEndpoint)?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    ensure!(
        (url.scheme() == "https" || (url.scheme() == "http" && loopback))
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        RkpError::InvalidEndpoint
    );
    let path = match url.path().trim_end_matches('/') {
        "" => "/v1",
        path => path,
    }
    .to_owned();
    url.set_path(&path);
    Ok(url)
}

pub(super) fn rpc_url(endpoint: &str, method: &str) -> Result<Url> {
    let mut url = endpoint_url(endpoint)?;
    url.set_path(&format!("{}:{method}", url.path()));
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| anyhow!("generate RPC request ID: {error}"))?;
    // UUID v4: random bits with the version and RFC variant fixed.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    let request_id = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    url.query_pairs_mut().append_pair("request_id", &request_id);
    Ok(url)
}

pub fn rkp_client() -> Result<Client> {
    let builder = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .retry(reqwest::retry::never());
    let builder = if cfg!(target_os = "android") {
        builder.tls_backend_preconfigured(duck_platform::net::embedded_rustls_config())
    } else {
        builder
    };
    Ok(builder.build()?)
}

pub async fn fetch_challenge(
    client: &Client,
    fingerprint: &str,
    server_url: &str,
) -> Result<Vec<u8>> {
    let url = rpc_url(server_url, "fetchEekChain")?;
    let payload = encode(&Value::Map(vec![
        (text("fingerprint"), text(fingerprint)),
        (text("id"), int(42)),
    ]))?;
    let response = client
        .post(url)
        .header("Content-Type", "application/cbor")
        .header("Accept", "application/cbor")
        .body(payload)
        .send()
        .await
        .map_err(|_| RkpError::ChallengeUnavailable)?;
    let status = response.status();
    let body = read_body(response, false).await?;
    if !status.is_success() {
        return Err(super::map_http_error(status, &body).into());
    }
    super::parse_challenge_response(&body)
}

pub(super) async fn read_body(mut response: Response, submitted: bool) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        if submitted {
            RkpError::SubmissionUnknown
        } else {
            RkpError::ChallengeUnavailable
        }
    })? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_RESPONSE,
            RkpError::InvalidRkpResponse("response exceeds size limit".into())
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
