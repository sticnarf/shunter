extern crate futures;
extern crate tokio_core;
#[macro_use]
extern crate tokio_io;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate num;
#[macro_use]
extern crate num_derive;

use futures::{Poll, Stream, Future, BoxFuture, Async, future};
use tokio_core::reactor::{Core, Handle, Timeout};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_io::io::{read_exact, write_all};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::{self, FromStr};
use std::borrow::BorrowMut;
use std::time::Duration;
use std::net::Shutdown;
use std::io::{self, Read, Write, ErrorKind};
use std::rc::Rc;
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
                non_send_box(write_all(socket, [SOCKS5_VERSION, NO_AUTHENTICATION_REQUIRED]).map(|(socket, _)| socket))
            } else {
                non_send_box(write_all(socket, [SOCKS5_VERSION, NO_ACCEPTABLE_METHODS]).and_then(|_| Err(io::Error::new(ErrorKind::Other, "Unsupported SOCKS version"))))
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
            AYTP::IPv4 => non_send_box(read_exact(socket, [0u8; 6]).map(|(socket, buf)| {
                let ip = IpAddr::from(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
                let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                (socket, SocketAddr::new(ip, port))
            })),
            AYTP::IPv6 => non_send_box(read_exact(socket, [0u8; 18]).map(|(socket, buf)| {
                let ip = IpAddr::from(Ipv6Addr::new(
                    (buf[0] as u16) << 8 | (buf[1] as u16), (buf[2] as u16) << 8 | (buf[3] as u16),
                    (buf[4] as u16) << 8 | (buf[5] as u16), (buf[6] as u16) << 8 | (buf[7] as u16),
                    (buf[8] as u16) << 8 | (buf[9] as u16), (buf[10] as u16) << 8 | (buf[11] as u16),
                    (buf[12] as u16) << 8 | (buf[13] as u16), (buf[14] as u16) << 8 | (buf[15] as u16)));
                let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                (socket, SocketAddr::new(ip, port))
            })),
            AYTP::DomainName => non_send_box(read_exact(socket, [0u8]).and_then(|(socket, buf)| {
                read_exact(socket, vec![0u8; (buf[0] as usize) + 2]).and_then(|(socket, buf)| {
                    // TODO: Resolve IP from DNS server
                    Ok((socket, SocketAddr::from_str("127.0.0.1:80").unwrap()))
                })
            }))
        }
    });
    let reply = req.and_then(move |(socket, socket_addr)| {
        TcpStream::connect(&socket_addr, &handle).then(move |res| {
            info!("Connecting {}", socket_addr);
            let mut reply_data = vec![SOCKS5_VERSION, SUCCEEDED_REPLY, RESERVED_CODE];
            match socket_addr {
                SocketAddr::V4(addr) => {
                    let ip = addr.ip().octets();
                    let port = addr.port();
                    reply_data.extend_from_slice(&[AYTP::IPv4 as u8, ip[0], ip[1], ip[2], ip[3], (port >> 8) as u8, port as u8])
                },
                SocketAddr::V6(addr) => {
                    let ip = addr.ip().octets();
                    let port = addr.port();
                    reply_data.extend_from_slice(&[AYTP::IPv6 as u8, ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                        ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
                        (port >> 8) as u8, port as u8]);
                }
            };
            match res {
                Ok(conn) => {
                    non_send_box(write_all(socket, reply_data).and_then(|(socket, buf)| Ok((socket, conn))))
                },
                Err(e) => {
                    reply_data[1] = GENERAL_SOCKS_SERVER_FAILURE_REPLY;
                    non_send_box(write_all(socket, reply_data).and_then(|_| Err(io::Error::new(ErrorKind::Other, "Connection failure"))))
                }
            }
        })
    });

    let passing = reply.and_then(|(socket, conn)| {
        info!("Ready for passing!");
        let socket = Rc::new(socket);
        let conn = Rc::new(conn);
        let client_to_server = Transfer {
            reader: socket.clone(),
            writer: conn.clone(),
            bytes_count: 0
        };
        let server_to_client = Transfer {
            reader: conn,
            writer: socket,
            bytes_count: 0
        };

        client_to_server.join(server_to_client)
    });

    non_send_box(passing.then(move |res| {
        match res {
            Ok((outbound, inbound)) => {
                info!("Outbound: {} bytes, inbound: {} bytes", outbound, inbound);
            },
            Err(e) => {
                info!("Error with client {}: {}", peer_address, e);
            }
        }
        Ok(())
    }))
}

struct Transfer {
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,
    bytes_count: usize
}

impl Future for Transfer {
    type Item = usize;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<usize, io::Error> {
        loop {
            let read_ready = self.reader.poll_read().is_ready();
            let write_ready = self.writer.poll_write().is_ready();
            if !(read_ready && write_ready) {
                return Ok(Async::NotReady);
            }

            let mut buf: [u8; 4096] = [0; 4096];
            let count = try_nb!((&*self.reader).read(&mut buf));
            if count == 0 {
                self.writer.shutdown(Shutdown::Write)?;
                return Ok(Async::Ready(self.bytes_count));
            }
            self.bytes_count += count;

            (&*self.writer).write(&buf[..count])?;
        }
    }
}

fn non_send_box<F: Future + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error>> {
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

const SUCCEEDED_REPLY: u8 = 0x00;
const GENERAL_SOCKS_SERVER_FAILURE_REPLY: u8 = 0x01;