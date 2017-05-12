use futures::{future, Future, BoxFuture, Stream};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Decoder, Encoder};
use tokio_proto::streaming::{Body, Message};
use tokio_proto::streaming::pipeline::{ServerProto, Frame};
use tokio_service::Service;
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::TcpStream;
use bytes::{BytesMut, ByteOrder, BigEndian};
use num::FromPrimitive;
use std::io;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub enum IncomingMessage {
    Negotiation(NegotiationMessage),
    Request(RequestMessage),
}

pub enum OutgoingMessage {

}

// Property names come after RFC 1928
struct NegotiationMessage {
    ver: SocksVersion,
    methods: Vec<u8>,
}

struct RequestMessage {
    ver: SocksVersion,
    cmd: SocksCommand,
    dst_addr: AddressType,
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
            // An incomplete head is received
            return Ok(None);
        }

        let nmethods = buf[1];
        let full_len = nmethods as usize + 2;
        if len < full_len {
            // An incomplete head is received
            return Ok(None);
        }

        let version = match FromPrimitive::from_u8(buf[0]) {
            Some(v) => v,
            None => return Err(io::Error::new(io::ErrorKind::Other, "Unknown protocol version")),
        };

        let message = NegotiationMessage {
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
        unimplemented!()
    }
}

impl Encoder for SocksCodec {
    type Item = Frame<OutgoingMessage, Vec<u8>, io::Error>;
    type Error = io::Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> io::Result<()> {
        unimplemented!()
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

