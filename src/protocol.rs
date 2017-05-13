use futures::BoxFuture;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Decoder, Encoder};
use tokio_proto::streaming::{Body, Message};
use tokio_proto::streaming::pipeline::{ServerProto, Frame};
use tokio_service::Service;
use bytes::{BytesMut, BufMut, BigEndian};
use num::FromPrimitive;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

pub enum IncomingMessage {
    Negotiation(IncomingNegotiationMessage),
    Request(IncomingRequestMessage),
}

pub enum OutgoingMessage {
    Negotiation(OutgoingNegotiationMessage),
    Request(OutgoingRequestMessage),
}

// Property names come after RFC 1928
pub struct IncomingNegotiationMessage {
    ver: SocksVersion,
    methods: Vec<u8>,
}

pub struct IncomingRequestMessage {
    ver: SocksVersion,
    cmd: SocksCommand,
    dst_addr: AddressType,
    port: u16,
}

pub struct OutgoingNegotiationMessage {
    ver: SocksVersion,
    method: u8,
}

pub struct OutgoingRequestMessage {
    ver: SocksVersion,
    rep: u8,
    bnd_addr: AddressType,
    port: u16,
}

enum Stage {
    Negotiation,
    Request,
}

pub struct SocksCodec {
    stage: Stage,
}

enum AddressType {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    DomainName(String),
}

#[derive(FromPrimitive)]
enum SocksVersion {
    V4 = 0x04,
    V5 = 0x05,
}

#[derive(FromPrimitive)]
enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

pub struct SocksProto;

impl Decoder for SocksCodec {
    type Item = Frame<IncomingMessage, Vec<u8>, io::Error>;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        match self.stage {
            Stage::Negotiation => self.decode_negotiation(buf),
            Stage::Request => self.decode_request(buf),
        }
    }
}

impl SocksCodec {
    fn decode_negotiation(&mut self,
                          buf: &mut BytesMut)
                          -> Result<Option<<Self as Decoder>::Item>, io::Error> {
        let len = buf.len();
        if len < 3 {
            return Ok(None);
        }

        let nmethods = buf[1];
        let full_len = nmethods as usize + 2;
        if len < full_len {
            return Ok(None);
        }

        let version = match FromPrimitive::from_u8(buf[0]) {
            Some(v) => v,
            None => return Err(io::Error::new(io::ErrorKind::Other, "Unknown protocol version")),
        };

        let message = IncomingNegotiationMessage {
            ver: version,
            methods: buf[2..full_len].to_vec(),
        };

        buf.split_to(full_len);
        self.stage = Stage::Request;

        Ok(Some(Frame::Message {
                    message: IncomingMessage::Negotiation(message),
                    body: false,
                }))
    }

    fn decode_request(&mut self,
                      buf: &mut BytesMut)
                      -> Result<Option<<Self as Decoder>::Item>, io::Error> {
        let len = buf.len();
        if len < 8 {
            return Ok(None);
        }

        let version = match FromPrimitive::from_u8(buf[0]) {
            Some(v) => v,
            None => return Err(io::Error::new(io::ErrorKind::Other, "Unknown protocol version")),
        };

        let command = match FromPrimitive::from_u8(buf[1]) {
            Some(v) => v,
            None => return Err(io::Error::new(io::ErrorKind::Other, "Unknown command")),
        };

        if buf[2] != 0x00 {
            // RSV must be X'00'
            return Err(io::Error::new(io::ErrorKind::Other, "Wrong RSV code"));
        }

        let full_len = match buf[3] {
            0x01 => 10,
            0x03 => buf[5] as usize + 7,
            0x04 => 22,
            _ => return Err(io::Error::new(io::ErrorKind::Other, "Unknown ATYP code")),
        };
        if len < full_len {
            return Ok(None);
        }

        let dst_addr = match buf[3] {
            0x01 => AddressType::Ipv4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])),
            0x03 => {
                let domain_name = match String::from_utf8(buf[6..(6 + buf[5] as usize)].to_vec()) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(io::Error::new(io::ErrorKind::Other, "Invalid domain name"))
                    }
                };
                AddressType::DomainName(domain_name)
            }
            0x04 => {
                AddressType::Ipv6(Ipv6Addr::new((buf[04] as u16) << 8 | (buf[05] as u16),
                                                (buf[06] as u16) << 8 | (buf[07] as u16),
                                                (buf[08] as u16) << 8 | (buf[09] as u16),
                                                (buf[10] as u16) << 8 | (buf[11] as u16),
                                                (buf[12] as u16) << 8 | (buf[13] as u16),
                                                (buf[14] as u16) << 8 | (buf[15] as u16),
                                                (buf[16] as u16) << 8 | (buf[17] as u16),
                                                (buf[18] as u16) << 8 | (buf[19] as u16)))
            }
            _ => return Err(io::Error::new(io::ErrorKind::Other, "Unknown ATYP code")),
        };

        let port = (buf[full_len - 2] as u16) << 8 | (buf[full_len - 1] as u16);

        let message = IncomingRequestMessage {
            ver: version,
            cmd: command,
            dst_addr: dst_addr,
            port: port,
        };

        Ok(Some(Frame::Message {
                    message: IncomingMessage::Request(message),
                    body: true,
                }))
    }
}

impl Encoder for SocksCodec {
    type Item = Frame<OutgoingMessage, Vec<u8>, io::Error>;
    type Error = io::Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> io::Result<()> {
        match msg {
            Frame::Message { message, body } => {
                match message {
                    OutgoingMessage::Negotiation(msg) => self.encode_negotiation(msg, body, buf),
                    OutgoingMessage::Request(msg) => self.encode_request(msg, body, buf),
                }
            }
            Frame::Body { chunk } => {
                match chunk {
                    Some(chunk) => self.encode_body(chunk, buf),
                    None => Ok(()),
                }
            }
            Frame::Error { error } => Err(error),
        }
    }
}

impl SocksCodec {
    fn encode_negotiation(&mut self,
                          msg: OutgoingNegotiationMessage,
                          body: bool,
                          buf: &mut BytesMut)
                          -> io::Result<()> {
        assert!(!body);
        buf.put_u8(msg.ver as u8);
        buf.put_u8(msg.method);
        Ok(())
    }

    fn encode_request(&mut self,
                      msg: OutgoingRequestMessage,
                      body: bool,
                      buf: &mut BytesMut)
                      -> io::Result<()> {
        buf.put_u8(msg.ver as u8);
        buf.put_u8(msg.rep);
        buf.put_u8(0x00);
        match msg.bnd_addr {
            AddressType::Ipv4(ip) => {
                buf.put_u8(0x01);
                buf.extend(&ip.octets());
            }
            AddressType::Ipv6(ip) => {
                buf.put_u8(0x04);
                buf.extend(&ip.octets());
            }
            AddressType::DomainName(domain_name) => {
                buf.put_u8(0x03);
                buf.put_u8(domain_name.len() as u8);
                buf.extend(domain_name.as_bytes());
            }
        };
        buf.put_u16::<BigEndian>(msg.port);
        Ok(())
    }

    fn encode_body(&mut self, msg: Vec<u8>, buf: &mut BytesMut) -> io::Result<()> {
        buf.extend(&msg);
        Ok(())
    }
}

impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for SocksProto {
    type Request = IncomingMessage;
    type RequestBody = Vec<u8>;
    type Response = OutgoingMessage;
    type ResponseBody = Vec<u8>;
    type Error = io::Error;

    type Transport = Framed<T, SocksCodec>;
    type BindTransport = Result<Self::Transport, io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Ok(io.framed(SocksCodec { stage: Stage::Negotiation }))
    }
}

pub struct LocalRedirect;

impl Service for LocalRedirect {
    type Request = Message<IncomingMessage, Body<Vec<u8>, io::Error>>;
    type Response = Message<OutgoingMessage, Body<Vec<u8>, io::Error>>;
    type Error = io::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn call(&self, req: Self::Request) -> Self::Future {
        unimplemented!()
    }
}

