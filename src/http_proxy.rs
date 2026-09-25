use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use hbb_common::{bail, log, tokio, ResultType};
use reqwest::blocking::Client;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::Method;

// The pinned hbb_common proto has no HttpProxyRequest/HttpProxyResponse, so the client's
// field 27 arrives as an unknown field and we speak the wire format by hand here. The
// message shapes must stay in sync with libs/hbb_common/protos/rendezvous.proto upstream:
//   HttpProxyRequest  { string method = 1; string path = 2; repeated HeaderEntry headers = 3; bytes body = 4; }
//   HttpProxyResponse { int32 status = 1; repeated HeaderEntry headers = 2; bytes body = 3; string error = 4; }
const HTTP_PROXY_REQUEST_FIELD: u64 = 27;
const HTTP_PROXY_RESPONSE_FIELD: u64 = 28;

const MAX_REQUEST_FRAME: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PATH_LEN: usize = 4 * 1024;
const MAX_HEADERS: usize = 64;

pub struct ProxyRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Default)]
pub struct ProxyResponse {
    pub status: i32,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub error: String,
}

impl ProxyResponse {
    fn failed(err: impl std::fmt::Display) -> Self {
        ProxyResponse {
            error: format!("{}", err),
            ..Default::default()
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = *self.buf.get(self.pos)?;
            self.pos += 1;
            if shift >= 64 {
                return None;
            }
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        let res = &self.buf[self.pos..end];
        self.pos = end;
        Some(res)
    }

    fn length_delimited(&mut self) -> Option<&'a [u8]> {
        let len = self.varint()? as usize;
        self.take(len)
    }

    fn skip(&mut self, wire_type: u64) -> Option<()> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => {
                self.take(8)?;
            }
            2 => {
                self.length_delimited()?;
            }
            5 => {
                self.take(4)?;
            }
            _ => return None,
        }
        Some(())
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        if value < 0x80 {
            out.push(value as u8);
            return;
        }
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
}

fn write_bytes_field(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    write_varint(out, (field << 3) | 2);
    write_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn encode_header_entry(name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + value.len() + 6);
    if !name.is_empty() {
        write_bytes_field(&mut out, 1, name.as_bytes());
    }
    if !value.is_empty() {
        write_bytes_field(&mut out, 2, value.as_bytes());
    }
    out
}

fn parse_header_entry(payload: &[u8]) -> Option<(String, String)> {
    let mut name = String::new();
    let mut value = String::new();
    let mut r = Reader::new(payload);
    while r.pos < r.buf.len() {
        let tag = r.varint()?;
        let wire_type = tag & 7;
        match tag >> 3 {
            1 if wire_type == 2 => name = std::str::from_utf8(r.length_delimited()?).ok()?.to_owned(),
            2 if wire_type == 2 => value = std::str::from_utf8(r.length_delimited()?).ok()?.to_owned(),
            _ => r.skip(wire_type)?,
        }
    }
    Some((name, value))
}

/// Extract the HttpProxyRequest (union field 27) from raw RendezvousMessage bytes.
/// Returns None for any other message, which keeps unknown-message handling unchanged.
pub fn parse_request_frame(bytes: &[u8]) -> Option<ProxyRequest> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_FRAME {
        return None;
    }
    let mut r = Reader::new(bytes);
    while r.pos < r.buf.len() {
        let tag = r.varint()?;
        let wire_type = tag & 7;
        let field = tag >> 3;
        if field == 0 {
            return None;
        }
        if field == HTTP_PROXY_REQUEST_FIELD && wire_type == 2 {
            let payload = r.length_delimited()?;
            return parse_http_proxy_request(payload);
        }
        r.skip(wire_type)?;
    }
    None
}

fn parse_http_proxy_request(payload: &[u8]) -> Option<ProxyRequest> {
    let mut req = ProxyRequest {
        method: String::new(),
        path: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let mut r = Reader::new(payload);
    while r.pos < r.buf.len() {
        let tag = r.varint()?;
        let wire_type = tag & 7;
        match tag >> 3 {
            1 if wire_type == 2 => {
                req.method = std::str::from_utf8(r.length_delimited()?).ok()?.to_owned()
            }
            2 if wire_type == 2 => {
                req.path = std::str::from_utf8(r.length_delimited()?).ok()?.to_owned()
            }
            3 if wire_type == 2 => {
                if req.headers.len() >= MAX_HEADERS {
                    return None;
                }
                let entry = parse_header_entry(r.length_delimited()?)?;
                req.headers.push(entry);
            }
            4 if wire_type == 2 => req.body = r.length_delimited()?.to_vec(),
            _ => r.skip(wire_type)?,
        }
    }
    Some(req)
}

/// Wrap a ProxyResponse as a RendezvousMessage carrying field 28, matching what
/// `write_to_bytes()` would emit once the server proto knows about HttpProxyResponse.
pub fn encode_response_frame(resp: &ProxyResponse) -> Vec<u8> {
    let mut payload = Vec::new();
    if resp.status != 0 {
        write_varint(&mut payload, (1 << 3) | 0);
        write_varint(&mut payload, resp.status.max(0) as u64);
    }
    for (name, value) in &resp.headers {
        write_bytes_field(&mut payload, 2, &encode_header_entry(name, value));
    }
    if !resp.body.is_empty() {
        write_bytes_field(&mut payload, 3, &resp.body);
    }
    if !resp.error.is_empty() {
        write_bytes_field(&mut payload, 4, resp.error.as_bytes());
    }
    let mut out = Vec::with_capacity(payload.len() + 8);
    write_bytes_field(&mut out, HTTP_PROXY_RESPONSE_FIELD, &payload);
    out
}

fn is_allowed_method(method: &str) -> bool {
    matches!(method, "GET" | "POST" | "PUT" | "DELETE")
}

fn path_allowed(path: &str) -> bool {
    path.starts_with("/api/")
        && path.len() <= MAX_PATH_LEN
        && !path.contains("..")
        && !path.contains('\\')
        && !path.contains(|c: char| c.is_control())
}

fn is_stripped_request_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

fn is_stripped_response_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "content-encoding"
    )
}

fn api_client() -> ResultType<&'static Client> {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let built = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(Policy::none())
        .build()?;
    Ok(CLIENT.get_or_init(|| built))
}

fn blocking_request(url: &str, req: ProxyRequest) -> ResultType<ProxyResponse> {
    let method = match req.method.as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        other => bail!("method not allowed: {}", other),
    };
    let mut builder = api_client()?.request(method, url);
    for (name, value) in &req.headers {
        if is_stripped_request_header(name) {
            continue;
        }
        match (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            (Ok(name), Ok(value)) => builder = builder.header(name, value),
            _ => log::debug!("http proxy: dropped invalid header {:?}", name),
        }
    }
    if !req.body.is_empty() {
        builder = builder.body(req.body);
    }
    let mut resp = builder.send()?;
    let status = resp.status().as_u16() as i32;
    let headers = resp
        .headers()
        .iter()
        .filter(|(name, _)| !is_stripped_response_header(name.as_str()))
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).to_string(),
            )
        })
        .collect();
    let mut body = Vec::new();
    (&mut resp)
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        bail!("response too large");
    }
    Ok(ProxyResponse {
        status,
        headers,
        body,
        error: String::new(),
    })
}

/// Forward a validated request to the local rustdesk-api over plain HTTP. Only called
/// after the caller proved the connection completed the encrypted key exchange.
pub async fn forward(req: ProxyRequest) -> ProxyResponse {
    if !is_allowed_method(&req.method) {
        return ProxyResponse::failed(format!("method not allowed: {}", req.method));
    }
    if !path_allowed(&req.path) {
        return ProxyResponse::failed("path not allowed");
    }
    let base = std::env::var("RUSTDESK_API_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:21114".to_owned());
    let url = format!("{}{}", base.trim_end_matches('/'), req.path);
    let url_log = url.clone();
    match tokio::task::spawn_blocking(move || blocking_request(&url, req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(err)) => {
            log::warn!("http proxy request to {} failed: {}", url_log, err);
            ProxyResponse::failed(err)
        }
        Err(err) => ProxyResponse::failed(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_test_request(req: &ProxyRequest) -> Vec<u8> {
        let mut payload = Vec::new();
        if !req.method.is_empty() {
            write_bytes_field(&mut payload, 1, req.method.as_bytes());
        }
        if !req.path.is_empty() {
            write_bytes_field(&mut payload, 2, req.path.as_bytes());
        }
        for (name, value) in &req.headers {
            write_bytes_field(&mut payload, 3, &encode_header_entry(name, value));
        }
        if !req.body.is_empty() {
            write_bytes_field(&mut payload, 4, &req.body);
        }
        let mut out = Vec::new();
        write_bytes_field(&mut out, HTTP_PROXY_REQUEST_FIELD, &payload);
        out
    }

    fn parse_response_frame(bytes: &[u8]) -> Option<(i64, Vec<(String, String)>, Vec<u8>, String)> {
        let mut r = Reader::new(bytes);
        let tag = r.varint()?;
        if (tag >> 3, tag & 7) != (HTTP_PROXY_RESPONSE_FIELD, 2) {
            return None;
        }
        let payload = r.length_delimited()?;
        let mut status = 0i64;
        let mut headers = Vec::new();
        let mut body = Vec::new();
        let mut error = String::new();
        let mut r = Reader::new(payload);
        while r.pos < r.buf.len() {
            let tag = r.varint()?;
            let wire_type = tag & 7;
            match tag >> 3 {
                1 if wire_type == 0 => status = r.varint()? as i64,
                2 if wire_type == 2 => headers.push(parse_header_entry(r.length_delimited()?)?),
                3 if wire_type == 2 => body = r.length_delimited()?.to_vec(),
                4 if wire_type == 2 => {
                    error = std::str::from_utf8(r.length_delimited()?).ok()?.to_owned()
                }
                _ => r.skip(wire_type)?,
            }
        }
        Some((status, headers, body, error))
    }

    #[test]
    fn request_roundtrip() {
        let req = ProxyRequest {
            method: "POST".to_owned(),
            path: "/api/currentUser".to_owned(),
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Authorization".to_owned(), "Bearer abc".to_owned()),
            ],
            body: b"{\"a\":1}".to_vec(),
        };
        let parsed = parse_request_frame(&encode_test_request(&req)).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/api/currentUser");
        assert_eq!(parsed.headers, req.headers);
        assert_eq!(parsed.body, req.body);
    }

    fn empty_request() -> ProxyRequest {
        ProxyRequest {
            method: String::new(),
            path: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn envelope_tag_bytes() {
        assert_eq!(&encode_test_request(&empty_request())[..2], &[0xDA, 0x01]);
        let frame = encode_response_frame(&ProxyResponse::default());
        assert_eq!(&frame[..2], &[0xE2, 0x01]);
    }

    #[test]
    fn skips_unknown_envelope_fields() {
        let mut frame = Vec::new();
        // an unrelated known-ish field (register-peer style, field 1) must not match
        write_bytes_field(&mut frame, 1, b"ignored");
        // a varint unknown field, must be skipped
        write_varint(&mut frame, (99 << 3) | 0);
        write_varint(&mut frame, 7);
        frame.extend_from_slice(&encode_test_request(&ProxyRequest {
            method: "GET".to_owned(),
            path: "/api/x".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }));
        let parsed = parse_request_frame(&frame).unwrap();
        assert_eq!(parsed.path, "/api/x");
    }

    #[test]
    fn rejects_malformed() {
        // no field 27 at all
        assert!(parse_request_frame(&write_bytes_field_owned(3, b"hello")).is_none());
        // truncated length-delimited payload
        let mut bad = Vec::new();
        write_varint(&mut bad, (HTTP_PROXY_REQUEST_FIELD << 3) | 2);
        write_varint(&mut bad, 100);
        bad.extend_from_slice(b"short");
        assert!(parse_request_frame(&bad).is_none());
        // garbage field number 0
        assert!(parse_request_frame(&[0x00, 0x00]).is_none());
    }

    fn write_bytes_field_owned(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_bytes_field(&mut out, field, data);
        out
    }

    #[test]
    fn response_roundtrip() {
        let resp = ProxyResponse {
            status: 404,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: b"{\"msg\":\"not found\"}".to_vec(),
            error: String::new(),
        };
        let (status, headers, body, error) = parse_response_frame(&encode_response_frame(&resp)).unwrap();
        assert_eq!(status, 404);
        assert_eq!(headers, resp.headers);
        assert_eq!(body, resp.body);
        assert_eq!(error, "");
    }

    #[test]
    fn response_failure_carries_error() {
        let resp = ProxyResponse::failed("connection refused");
        let (status, _, body, error) = parse_response_frame(&encode_response_frame(&resp)).unwrap();
        assert_eq!(status, 0);
        assert!(body.is_empty());
        assert_eq!(error, "connection refused");
    }

    #[test]
    fn path_and_method_policy() {
        assert!(path_allowed("/api/currentUser"));
        assert!(path_allowed("/api/sysinfo?x=1"));
        assert!(!path_allowed("/admin"));
        assert!(!path_allowed("//evil.com/api/x"));
        assert!(!path_allowed("/api/../secret"));
        assert!(!path_allowed("/api/\\evil"));
        assert!(!path_allowed("/api/\ninject"));
        assert!(is_allowed_method("POST"));
        assert!(!is_allowed_method("CONNECT"));
    }
}
