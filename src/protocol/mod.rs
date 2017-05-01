extern crate futures;
extern crate tokio_io;
extern crate tokio_proto;
extern crate tokio_service;
extern crate bytes;

use self::futures::{future, Future, BoxFuture};

use self::tokio_io::{AsyncRead, AsyncWrite};
use self::tokio_io::codec::{Framed, Decoder, Encoder};

use self::tokio_proto::streaming::{Body, Message};
use self::tokio_proto::streaming::pipeline::{ServerProto, Frame};

use self::tokio_service::Service;

use self::bytes::{BytesMut, ByteOrder, BigEndian};

use std::io;

enum Stage {
    NEGOTIATION,
    REQUESTING,
}

pub struct SocksCodec {
    stage: Stage,
}

#[derive(Debug)]
pub enum AddressType {
    IP_V4,
    DOMAIN_NAME,
    IP_V6,
}

#[derive(Debug)]
pub enum RequestItem {
    NEGOTIATION { methods: Vec<u8> },
    REQUESTING {
        command: RequestCommand,
        address_type: AddressType,
        dest_addr: Vec<u8>,
        dest_port: u16,
    },
}

#[derive(Debug)]
enum RequestCommand {
    CONNECT,
    BIND,
    UDP_ASSOCIATE,
}

impl Decoder for SocksCodec {
    type Item = Frame<RequestItem, Vec<u8>, io::Error>;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        match self.stage {
            Stage::NEGOTIATION => {
                if buf.len() < 3 {
                    return Ok(None);
                }
                let head = buf.split_to(2);
                match head[0] {
                    // SOCKS v5
                    0x05 => {
                        self.stage = Stage::REQUESTING;
                        Ok(Some(Frame::Message {
                                    message: RequestItem::NEGOTIATION {
                                        methods: buf.split_to(head[1] as usize).to_vec(),
                                    },
                                    body: false,
                                }))
                    }
                    _ => Err(io::Error::new(io::ErrorKind::Other, "Unsupported protocol version")),
                }
            }
            Stage::REQUESTING => {
                if buf.len() < 8 {
                    return Ok(None);
                }
                let head = buf.split_to(4);
                match head[0] {
                    // SOCKS v5
                    0x05 => {
                        let command = match head[1] {
                            0x01 => RequestCommand::CONNECT,
                            0x02 => RequestCommand::BIND,
                            0x03 => RequestCommand::UDP_ASSOCIATE,
                            _ => {
                                return Err(io::Error::new(io::ErrorKind::Other,
                                                          "Unsupported command"))
                            }
                        };
                        if head[2] != 0x00 {
                            return Err(io::Error::new(io::ErrorKind::Other, "Wrong reserved code"));
                        }
                        let (address_type, addr_len) = match head[3] {
                            0x01 => (AddressType::IP_V4, 4),
                            0x04 => (AddressType::IP_V6, 16),
                            0x03 => (AddressType::DOMAIN_NAME, buf.split_to(1)[0]),
                            _ => {
                                return Err(io::Error::new(io::ErrorKind::Other,
                                                          "Unsupported address type"))
                            }
                        };
                        Ok(Some(Frame::Message {
                                    message: RequestItem::REQUESTING {
                                        command: command,
                                        address_type: address_type,
                                        dest_addr: buf.split_to(addr_len as usize).to_vec(),
                                        dest_port: BigEndian::read_u16(&buf.split_to(2)),
                                    },
                                    body: true,
                                }))
                    }
                    _ => Err(io::Error::new(io::ErrorKind::Other, "Unsupported protocol version")),
                }
            }
        }
    }
}

impl Encoder for SocksCodec {
    type Item = Frame<Vec<u8>, Vec<u8>, io::Error>;
    type Error = io::Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> io::Result<()> {
        match msg {
            Frame::Message { message, body } => {
                buf.extend(&message);
            }
            Frame::Body { chunk } => {
                if let Some(chunk) = chunk {
                    buf.extend(&chunk);
                }
            }
            Frame::Error { error } => return Err(error),
        }
        Ok(())
    }
}

pub struct SocksProto;

impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for SocksProto {
    type Request = RequestItem;
    type RequestBody = Vec<u8>;
    type Response = Vec<u8>;
    type ResponseBody = Vec<u8>;
    type Error = io::Error;

    type Transport = Framed<T, SocksCodec>;
    type BindTransport = Result<Self::Transport, io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Ok(io.framed(SocksCodec { stage: Stage::NEGOTIATION }))
    }
}

pub struct Proxy;

impl Service for Proxy {
    type Request = Message<RequestItem, Body<Vec<u8>, io::Error>>;
    type Response = Message<Vec<u8>, Body<Vec<u8>, io::Error>>;

    type Error = io::Error;

    type Future = BoxFuture<Self::Response, Self::Error>;

    fn call(&self, req: Self::Request) -> Self::Future {
        println!("{:?}", req);
        match req {
            Message::WithoutBody(req) => {
                match req {
                    RequestItem::NEGOTIATION { methods } => {
                        if methods.iter().any(|&x| x == 0x00) {
                            future::ok(Message::WithoutBody(vec![0x05, 0x00])).boxed()
                        } else {
                            future::ok(Message::WithoutBody(vec![0x05, 0xFF])).boxed()
                        }
                    }
                    RequestItem::REQUESTING {
                        command,
                        address_type,
                        dest_addr,
                        dest_port,
                    } => {
                        
                    }
                }
            }
            _ => unimplemented!(),
        }
    }
}

