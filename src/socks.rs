use futures::Future;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

pub trait FutureExt<F: Future> {
    fn into_box(self) -> Box<Future<Item=F::Item, Error=F::Error>>;
}

impl<F: Future + 'static> FutureExt<F> for F {
    fn into_box(self) -> Box<Future<Item=F::Item, Error=F::Error>> {
        Box::new(self)
    }
}

#[macro_export]
macro_rules! tokio_err {
    ($msg:expr) => ({
        use std::io::{self, ErrorKind};
        Err(io::Error::new(ErrorKind::Other, $msg))
    });
}

// Only SOCKS version 5 is supported
#[macro_export]
macro_rules! check_socks_version {
    ($v:expr) => {
        if $v != SOCKS5_VERSION {
            return tokio_err!("Unsupported SOCKS version");
        }
    };
}

pub trait BinaryAddress {
    fn extract_addr(self) -> SocketAddr;
}

// 6 bytes for IPv4
impl BinaryAddress for [u8; 6] {
    fn extract_addr(self) -> SocketAddr {
        let ip = IpAddr::from(Ipv4Addr::new(self[0], self[1], self[2], self[3]));
        let port = ((self[4] as u16) << 8) | (self[5] as u16);
        SocketAddr::new(ip, port)
    }
}

// 18 bytes for IPv6
impl BinaryAddress for [u8; 18] {
    fn extract_addr(self) -> SocketAddr {
        let ip = IpAddr::from(Ipv6Addr::new(
            ((self[0] as u16) << 8) | (self[1] as u16),
            ((self[2] as u16) << 8) | (self[3] as u16),
            ((self[4] as u16) << 8) | (self[5] as u16),
            ((self[6] as u16) << 8) | (self[7] as u16),
            ((self[8] as u16) << 8) | (self[9] as u16),
            ((self[10] as u16) << 8) | (self[11] as u16),
            ((self[12] as u16) << 8) | (self[13] as u16),
            ((self[14] as u16) << 8) | (self[15] as u16),
        ));
        let port = ((self[16] as u16) << 8) | (self[17] as u16);
        SocketAddr::new(ip, port)
    }
}

#[repr(u8)]
#[derive(FromPrimitive, Debug, Clone, Copy)]
pub enum AYTP {
    IPv4 = 0x01,
    IPv6 = 0x04,
    DomainName = 0x03,
}

pub const SOCKS5_VERSION: u8 = 0x05;

pub const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
pub const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

pub const CONNECT_CMD: u8 = 0x01;

pub const RESERVED_CODE: u8 = 0x00;

pub const SUCCEEDED_REPLY: u8 = 0x00;
pub const GENERAL_SOCKS_SERVER_FAILURE_REPLY: u8 = 0x01;