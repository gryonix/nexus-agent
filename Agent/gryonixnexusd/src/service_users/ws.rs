//! A minimal WebSocket client for a service on this machine's loopback

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::Refusal;

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;
const MAX_MESSAGE: usize = 8 * 1024 * 1024;
const HEADER_LIMIT: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

pub fn encode_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    match payload.len() {
        0..=125 => out.push(0x80 | payload.len() as u8),
        126..=65535 => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        length => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(index, byte)| byte ^ mask[index % 4]));
    out
}

pub fn decode_frame(bytes: &[u8]) -> Option<(Frame, usize)> {
    let (first, second) = (*bytes.first()?, *bytes.get(1)?);
    let masked = second & 0x80 != 0;
    let (length, mut offset) = match second & 0x7f {
        126 => (u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]) as usize, 4),
        127 => (u64::from_be_bytes(bytes.get(2..10)?.try_into().ok()?) as usize, 10),
        short => (short as usize, 2),
    };
    let mask: Option<[u8; 4]> = if masked { Some(bytes.get(offset..offset + 4)?.try_into().ok()?) } else { None };
    if masked {
        offset += 4;
    }
    let body = bytes.get(offset..offset.checked_add(length)?)?;
    let payload = match mask {
        Some(key) => body.iter().enumerate().map(|(index, byte)| byte ^ key[index % 4]).collect(),
        None => body.to_vec(),
    };
    Some((Frame { fin: first & 0x80 != 0, opcode: first & 0x0f, payload }, offset + length))
}

fn four_bytes() -> [u8; 4] {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0x5a5a);
    nanos.to_be_bytes()
}

pub fn handshake_request(port: u16, path: &str) -> String {
    let seed = four_bytes();
    let key: Vec<u8> = (0..16).map(|index| seed[index % 4] ^ (index as u8).wrapping_mul(17)).collect();
    let key = base64::engine::general_purpose::STANDARD.encode(key);
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n"
    )
}

pub fn upgrade_accepted(head: &str) -> bool {
    head.lines().next().is_some_and(|line| line.split_whitespace().nth(1) == Some("101"))
}

pub struct Socket {
    stream: TcpStream,
    pending: Vec<u8>,
}

impl Socket {
    pub async fn connect(port: u16, path: &str) -> Result<Socket, Refusal> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.map_err(|_| Refusal::ServiceDown)?;
        stream.write_all(handshake_request(port, path).as_bytes()).await.map_err(|_| Refusal::ServiceDown)?;
        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        let end = loop {
            if let Some(position) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
            if head.len() > HEADER_LIMIT {
                return Err(Refusal::Failed);
            }
            let read = stream.read(&mut chunk).await.map_err(|_| Refusal::ServiceDown)?;
            if read == 0 {
                return Err(Refusal::ServiceDown);
            }
            head.extend_from_slice(&chunk[..read]);
        };
        if !upgrade_accepted(&String::from_utf8_lossy(&head[..end])) {
            return Err(Refusal::Failed);
        }
        Ok(Socket { stream, pending: head[end..].to_vec() })
    }

    pub async fn send(&mut self, text: &str) -> Result<(), Refusal> {
        self.write(OPCODE_TEXT, text.as_bytes()).await
    }

    async fn write(&mut self, opcode: u8, payload: &[u8]) -> Result<(), Refusal> {
        let frame = encode_frame(opcode, payload, four_bytes());
        self.stream.write_all(&frame).await.map_err(|_| Refusal::ServiceDown)
    }

    async fn next_frame(&mut self) -> Result<Frame, Refusal> {
        loop {
            if let Some((frame, used)) = decode_frame(&self.pending) {
                self.pending.drain(..used);
                return Ok(frame);
            }
            let mut chunk = [0u8; 8192];
            let read = self.stream.read(&mut chunk).await.map_err(|_| Refusal::ServiceDown)?;
            if read == 0 {
                return Err(Refusal::ServiceDown);
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }

    pub async fn receive(&mut self) -> Result<String, Refusal> {
        let mut message: Vec<u8> = Vec::new();
        loop {
            let frame = self.next_frame().await?;
            match frame.opcode {
                OPCODE_PING => self.write(OPCODE_PONG, &frame.payload).await?,
                OPCODE_PONG => {}
                OPCODE_CLOSE => return Err(Refusal::ServiceDown),
                OPCODE_TEXT | OPCODE_CONTINUATION => {
                    message.extend_from_slice(&frame.payload);
                    if message.len() > MAX_MESSAGE {
                        return Err(Refusal::Failed);
                    }
                    if frame.fin {
                        return String::from_utf8(message).map_err(|_| Refusal::Failed);
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASK: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

    #[test]
    fn a_short_frame_is_masked_and_reads_back() {
        let bytes = encode_frame(OPCODE_TEXT, b"hello", MASK);
        assert_eq!(bytes[0], 0x81);
        assert_eq!(bytes[1], 0x80 | 5);
        assert_ne!(&bytes[6..], b"hello");
        let (frame, used) = decode_frame(&bytes).unwrap();
        assert_eq!((frame.fin, frame.opcode, frame.payload.as_slice(), used), (true, OPCODE_TEXT, &b"hello"[..], bytes.len()));
    }

    #[test]
    fn long_payloads_use_the_extended_lengths() {
        let medium = vec![b'a'; 300];
        let bytes = encode_frame(OPCODE_TEXT, &medium, MASK);
        assert_eq!(bytes[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 300);
        assert_eq!(decode_frame(&bytes).unwrap().0.payload, medium);
        let large = vec![b'b'; 70_000];
        let bytes = encode_frame(OPCODE_TEXT, &large, MASK);
        assert_eq!(bytes[1], 0x80 | 127);
        assert_eq!(decode_frame(&bytes).unwrap().0.payload.len(), 70_000);
    }

    #[test]
    fn unmasked_server_frames_decode_and_partial_ones_wait() {
        let mut bytes = vec![0x81, 0x03];
        bytes.extend_from_slice(b"abc");
        bytes.extend_from_slice(&[0x81, 0x02, b'x']);
        let (frame, used) = decode_frame(&bytes).unwrap();
        assert_eq!((frame.payload.as_slice(), used), (&b"abc"[..], 5));
        assert!(decode_frame(&bytes[used..]).is_none());
        assert!(decode_frame(&[]).is_none() && decode_frame(&[0x81]).is_none());
    }

    #[test]
    fn a_fragment_is_not_the_last_and_control_codes_pass_through() {
        let (frame, _) = decode_frame(&[0x01, 0x01, b'a']).unwrap();
        assert!(!frame.fin && frame.opcode == OPCODE_TEXT);
        let (ping, _) = decode_frame(&[0x89, 0x00]).unwrap();
        assert_eq!(ping.opcode, OPCODE_PING);
    }

    #[test]
    fn the_handshake_asks_for_an_upgrade_as_a_trusted_proxy_client() {
        let request = handshake_request(8123, "/api/websocket");
        assert!(request.starts_with("GET /api/websocket HTTP/1.1\r\nHost: 127.0.0.1:8123\r\n"));
        assert!(request.contains("Upgrade: websocket\r\n") && request.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(request.contains("X-Forwarded-For: 127.0.0.1\r\n") && request.ends_with("\r\n\r\n"));
        assert!(upgrade_accepted("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"));
        assert!(!upgrade_accepted("HTTP/1.1 400 Bad Request\r\n\r\n"));
    }
}
