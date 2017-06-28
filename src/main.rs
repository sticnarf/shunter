extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate num;
#[macro_use]
extern crate num_derive;

use futures::{Stream, Future, BoxFuture, future};
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_io::io::{read_exact, write_all};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;
use std::str::FromStr;
use std::io;
use std::io::ErrorKind;
use num::FromPrimitive;

fn main() {
    drop(env_logger::init().unwrap());

    let mut core = Core::new().expect("Unable to create reactor");
    let handle = core.handle();

    let address = "0.0.0.0:12345".parse().unwrap();
    let listener = TcpListener::bind(&address, &handle).expect(&format!("Unable to bind to address: {}", address));

    let connections = listener.incoming();
    let server = connections.for_each(|(socket, peer_address)| {
        info!("Listen to client: {}", peer_address);
        serve(socket, peer_address, handle.clone())
    });
    core.run(server).ok();
}

fn serve(socket: TcpStream, peer_address: SocketAddr, handle: Handle) -> Box<Future<Item=(), Error=io::Error>> {
    let auth = read_exact(socket, [0u8; 2]).and_then(|(socket, buf)| {
        if buf[0] != SOCKS5_VERSION {
            return Err(io::Error::new(ErrorKind::Other, "Unsupported SOCKS version"));
        }
        Ok((socket, buf[1]))
    }).and_then(|(socket, method_cnt)| {
        read_exact(socket, vec![0u8; method_cnt as usize]).and_then(|(socket, buf)| {
            if buf.iter().any(|&x| x == NO_AUTHENTICATION_REQUIRED) {
                mybox(write_all(socket, [SOCKS5_VERSION, NO_AUTHENTICATION_REQUIRED]).map(|(socket, _)| socket))
            } else {
                mybox(write_all(socket, [SOCKS5_VERSION, NO_ACCEPTABLE_METHODS]).and_then(|_| Err(io::Error::new(ErrorKind::Other, "Unsupported SOCKS version"))))
            }
        })
    });

    let req = auth.and_then(|socket| {
        read_exact(socket, [0u8; 4]).and_then(|(socket, buf)| {
            if buf[0] != SOCKS5_VERSION {
                return Err(io::Error::new(ErrorKind::Other, "Unsupported SOCKS version"));
            }
            if buf[1] != CONNECT_CMD {
                return Err(io::Error::new(ErrorKind::Other, "Unsupported command"));
            }
            if buf[2] != RESERVED_CODE {
                return Err(io::Error::new(ErrorKind::Other, "Unexpected reserved code"));
            }
            match FromPrimitive::from_u8(buf[3]) {
                Some(aytp) => Ok((socket, aytp)),
                None => Err(io::Error::new(ErrorKind::Other, "Unknown AYTP"))
            }
        })
    }).and_then(|(socket, aytp)| {
        match aytp {
            AYTP::IPv4 => mybox(read_exact(socket, [0u8; 6]).map(|(socket, buf)| {
                let ip = IpAddr::from(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
                let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                (socket, SocketAddr::new(ip, port))
            })),
            AYTP::IPv6 => mybox(read_exact(socket, [0u8; 18]).map(|(socket, buf)| {
                let ip = IpAddr::from(Ipv6Addr::new(
                    (buf[0] as u16) << 8 | (buf[1] as u16), (buf[2] as u16) << 8 | (buf[3] as u16),
                    (buf[4] as u16) << 8 | (buf[5] as u16), (buf[6] as u16) << 8 | (buf[7] as u16),
                    (buf[8] as u16) << 8 | (buf[9] as u16), (buf[10] as u16) << 8 | (buf[11] as u16),
                    (buf[12] as u16) << 8 | (buf[13] as u16), (buf[14] as u16) << 8 | (buf[15] as u16)));
                let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                (socket, SocketAddr::new(ip, port))
            })),
            AYTP::DomainName => mybox(read_exact(socket, [0u8]).and_then(|(socket, buf)| {
                read_exact(socket, vec![0u8; (buf[0] as usize) + 2]).and_then(|(socket, buf)| {
                    // TODO: Resolve IP from DNS server
                    Ok((socket, SocketAddr::from_str("127.0.0.1:80").unwrap()))
                })
            }))
        }
    });

    let reply = req.and_then(move |(socket, socket_addr)| {
        TcpStream::connect(&socket_addr, &handle).then(|conn| {
            // TODO: Connect to remote server
            Ok(())
        })
    });

    mybox(reply.then(move |res| {
        if let Err(e) = res {
            info!("Error with client {}: {}", peer_address, e);
        }
        Ok(())
    }))
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error>> {
    Box::new(f)
}

#[repr(u8)]
#[derive(FromPrimitive)]
enum AYTP {
    IPv4 = 0x01,
    IPv6 = 0x03,
    DomainName = 0x04
}

const SOCKS5_VERSION: u8 = 0x05;

const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

const CONNECT_CMD: u8 = 0x01;

const RESERVED_CODE: u8 = 0x00;