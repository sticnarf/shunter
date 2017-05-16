use futures::{future, Future, Stream, Sink};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Decoder, Encoder};
use tokio_proto::streaming::{Body, Message};
use tokio_proto::streaming::pipeline::{ServerProto, Frame};
use tokio_service::Service;
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use bytes::{BytesMut, BufMut, BigEndian};
use trust_dns::client::{BasicClientHandle, ClientHandle};
use trust_dns::rr::{Name, DNSClass, RecordType, RData};
use trust_dns::op::ResponseCode;
use num::FromPrimitive;
use std::str;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, IpAddr};

#[derive(Clone)]
pub enum IncomingMessage {
    Negotiation(IncomingNegotiationMessage),
    Request(IncomingRequestMessage),
}

pub enum OutgoingMessage {
    Negotiation(OutgoingNegotiationMessage),
    Request(OutgoingRequestMessage),
}

// Property names come after RFC 1928
#[derive(Clone)]
pub struct IncomingNegotiationMessage {
    ver: SocksVersion,
    methods: Vec<u8>,
}

#[derive(Clone)]
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

#[derive(Clone)]
enum AddressType {
    Ip(IpAddr),
    DomainName(Name),
}

#[derive(Copy, Clone, PartialEq, FromPrimitive)]
enum SocksVersion {
    V4 = 0x04,
    V5 = 0x05,
}

#[derive(Copy, Clone, PartialEq, FromPrimitive)]
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
            0x01 => AddressType::Ip(IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]))),
            0x03 => {
                let domain_name = match str::from_utf8(&buf[6..(6 + buf[5] as usize)]) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(io::Error::new(io::ErrorKind::Other, "Invalid domain name"))
                    }
                };
                let domain_name = match Name::parse(domain_name, None) {
                    Ok(name) => name,
                    Err(_) => {
                        return Err(io::Error::new(io::ErrorKind::Other, "Invalid domain name"))
                    }
                };
                AddressType::DomainName(domain_name)
            }
            0x04 => {
                AddressType::Ip(IpAddr::V6(Ipv6Addr::new((buf[04] as u16) << 8 | (buf[05] as u16),
                                                         (buf[06] as u16) << 8 | (buf[07] as u16),
                                                         (buf[08] as u16) << 8 | (buf[09] as u16),
                                                         (buf[10] as u16) << 8 | (buf[11] as u16),
                                                         (buf[12] as u16) << 8 | (buf[13] as u16),
                                                         (buf[14] as u16) << 8 | (buf[15] as u16),
                                                         (buf[16] as u16) << 8 | (buf[17] as u16),
                                                         (buf[18] as u16) << 8 | (buf[19] as u16))))
            }
            _ => unreachable!(),
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
            AddressType::Ip(ip) => {
                match ip {
                    IpAddr::V4(ip) => {
                        buf.put_u8(0x01);
                        buf.extend(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        buf.put_u8(0x04);
                        buf.extend(&ip.octets());
                    }
                }
            }

            // AddressType::DomainName(domain_name) => {
            //     buf.put_u8(0x03);
            //     buf.put_u8(domain_name.len() as u8);
            //     buf.extend(domain_name.to_string().as_bytes());
            // }
            AddressType::DomainName(_) => unreachable!(),
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

pub struct LocalRedirect {
    pub ev_handle: Handle,
    pub dns_client: BasicClientHandle,
}

impl Service for LocalRedirect {
    type Request = Message<IncomingMessage, Body<Vec<u8>, io::Error>>;
    type Response = Message<OutgoingMessage, Body<Vec<u8>, io::Error>>;
    type Error = io::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        match req {
            Message::WithoutBody(msg) => {
                match msg {
                    IncomingMessage::Negotiation(msg) => self.serve_negotiation(msg),
                    IncomingMessage::Request(_) => {
                        return Box::new(future::err(io::Error::new(io::ErrorKind::Other,
                                                                   "Body missing")))
                    }
                }
            }
            Message::WithBody(msg, body) => {
                match msg {
                    IncomingMessage::Negotiation(_) => {
                        return Box::new(future::err(io::Error::new(io::ErrorKind::Other,
                                                                   "Unexpected body")))
                    }
                    IncomingMessage::Request(msg) => self.serve_request(msg, body),
                }
            }
        }
    }
}

impl LocalRedirect {
    fn serve_negotiation(&self, msg: IncomingNegotiationMessage) -> <Self as Service>::Future {
        // Only Socks5 is supported
        if msg.ver != SocksVersion::V5 {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other,
                                                       "Unsupported socks version")));
        };

        // No authentication method is supported yet
        let method = if msg.methods.iter().any(|&m| m == 0x00) {
            0x00
        } else {
            0xFF
        };

        let message = OutgoingMessage::Negotiation(OutgoingNegotiationMessage {
                                                       ver: msg.ver,
                                                       method: method,
                                                   });

        Box::new(future::ok(Message::WithoutBody(message)))
    }

    fn serve_request(&self,
                     msg: IncomingRequestMessage,
                     body: Body<Vec<u8>, io::Error>)
                     -> <Self as Service>::Future {
        // Only Socks5 is supported
        if msg.ver != SocksVersion::V5 {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other,
                                                       "Unsupported socks version")));
        };

        // Only CONNECT command is supported
        if msg.cmd != SocksCommand::Connect {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other,
                                                       "Unsupported command")));
        };

        let port = msg.port;

        let addr = Box::new(self.resolve_addr(msg.dst_addr)
                                .map(move |ip| (ip, SocketAddr::new(ip, port))));

        let handle = self.ev_handle.clone();

        let transfer = addr.map(move |(ip, addr)| {
                TcpStream::connect(&addr, &handle)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, "Connection error"))
                    .map(move |conn| {
                        let (sender, client_body) = Body::<Vec<u8>, io::Error>::pair();
                        let framed = conn.framed(RedirectCodec);
                        let (sink, stream) = framed.split();
                        let from_client = sink.send_all(body);
                        let to_client = sender
                            .sink_map_err(|e| io::Error::new(io::ErrorKind::Other, "Sender error"))
                            .send_all(stream);
                        from_client.join(to_client);
                        let msg = OutgoingRequestMessage {
                            ver: SocksVersion::V5,
                            rep: 0x00,
                            bnd_addr: AddressType::Ip(ip),
                            port: port,
                        };
                        Message::WithBody(OutgoingMessage::Request(msg), client_body)
                    })

            })
            .and_then(|msg| msg);
        Box::new(transfer)
    }

    fn resolve_addr(&self, addr: AddressType) -> Box<Future<Item = IpAddr, Error = io::Error>> {
        match addr {
            AddressType::Ip(addr) => Box::new(future::ok(addr)),
            AddressType::DomainName(domain_name) => {
                let mut dns_client = self.dns_client.clone();
                let record = dns_client
                    .query(domain_name, DNSClass::IN, RecordType::A)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, "DNS error"))
                    .and_then(|m| if m.response_code() != ResponseCode::NoError {
                                  future::err(io::Error::new(io::ErrorKind::Other, "DNS error"))
                              } else {
                                  let ip = m.answers()
                                      .iter()
                                      .filter_map(|record| match record.rdata() {
                                                      &RData::A(ip) => Some(IpAddr::V4(ip)),
                                                      &RData::AAAA(ip) => Some(IpAddr::V6(ip)),
                                                      _ => None,
                                                  })
                                      .next();
                                  match ip {
                                      Some(ip) => future::ok(ip),
                                      None => {
                                          future::err(io::Error::new(io::ErrorKind::Other,
                                                                     "DNS record not found"))
                                      }
                                  }
                              });
                Box::new(record)
                // record.boxed()
            }
        }
    }
}

pub struct RedirectCodec;

impl Decoder for RedirectCodec {
    type Item = Result<Vec<u8>, io::Error>;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        let buf = buf.take();
        if buf.len() > 0 {
            Ok(Some(Ok(buf.to_vec())))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for RedirectCodec {
    type Item = Vec<u8>;
    type Error = io::Error;
    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> io::Result<()> {
        buf.extend(&msg);
        Ok(())
    }
}

