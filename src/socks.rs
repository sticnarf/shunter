use futures::{Poll, Future, Async};
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use tokio_io::io::{read_exact, write_all};
use tokio_dns::{CpuPoolResolver, Resolver};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;
use std::net::Shutdown;
use std::io::{self, Read, Write, ErrorKind};
use std::rc::Rc;
use num::FromPrimitive;
use redirect::{self, Proxy};
use constants::socks::*;
use FutureExt;

pub fn serve(
    socket: TcpStream,
    peer_address: SocketAddr,
    handle: Handle,
    resolver: CpuPoolResolver,
) -> Box<Future<Item=(), Error=io::Error>> {
    // Read the SOCKS version and the number of methods the client supports
    let auth = read_exact(socket, [0u8; 2]).and_then(|(socket, buf)| {
        if buf[0] != SOCKS5_VERSION {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Unsupported SOCKS version",
            ));
        }
        Ok((socket, buf[1]))
    }).and_then(|(socket, method_cnt)|
        // Read the acceptable methods
        read_exact(socket, vec![0u8; method_cnt as usize]).and_then(|(socket, buf)|
            // No authentication method is supported at this stage
            if buf.iter().any(|&x| x == NO_AUTHENTICATION_REQUIRED) {
                write_all(socket, [SOCKS5_VERSION, NO_AUTHENTICATION_REQUIRED])
                    .map(|(socket, _)| socket).into_box()
            } else {
                write_all(socket, [SOCKS5_VERSION, NO_ACCEPTABLE_METHODS]).and_then(|_| {
                    Err(io::Error::new(
                        ErrorKind::Other,
                        "No acceptable authentication methods",
                    ))
                }).into_box()
            })
    );

    let req = auth.and_then(|socket| {
        read_exact(socket, [0u8; 4]).and_then(|(socket, buf)| {
            if buf[0] != SOCKS5_VERSION {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    "Unsupported SOCKS version",
                ));
            }
            if buf[1] != CONNECT_CMD {
                return Err(io::Error::new(ErrorKind::Other, "Unsupported command"));
            }
            if buf[2] != RESERVED_CODE {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    format!("Expect reserved code, but {}", buf[2]),
                ));
            }
            match FromPrimitive::from_u8(buf[3]) {
                Some(aytp) => {
                    debug!("AYTP: {:?}", aytp);
                    Ok((socket, aytp))
                }
                None => Err(io::Error::new(ErrorKind::Other, "Unknown AYTP")),
            }
        })
    }).and_then(move |(socket, aytp)| match aytp {
        AYTP::IPv4 => non_send_box(read_exact(socket, [0u8; 6]).map(|(socket, buf)| {
            let ip = IpAddr::from(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
            (socket, SocketAddr::new(ip, port))
        })),
        AYTP::IPv6 => non_send_box(read_exact(socket, [0u8; 18]).map(|(socket, buf)| {
            let ip = IpAddr::from(Ipv6Addr::new(
                ((buf[0] as u16) << 8) | (buf[1] as u16),
                ((buf[2] as u16) << 8) | (buf[3] as u16),
                ((buf[4] as u16) << 8) | (buf[5] as u16),
                ((buf[6] as u16) << 8) | (buf[7] as u16),
                ((buf[8] as u16) << 8) | (buf[9] as u16),
                ((buf[10] as u16) << 8) | (buf[11] as u16),
                ((buf[12] as u16) << 8) | (buf[13] as u16),
                ((buf[14] as u16) << 8) | (buf[15] as u16),
            ));
            let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
            (socket, SocketAddr::new(ip, port))
        })),
        AYTP::DomainName => non_send_box(
            read_exact(socket, [0u8])
                .and_then(|(socket, buf)| {
                    let domain_len = buf[0] as usize;
                    read_exact(socket, vec![0u8; domain_len + 2]).and_then(
                        move |(socket, buf)| {
                            let domain = match str::from_utf8(&buf[..domain_len]) {
                                Ok(domain) => domain,
                                Err(_) => {
                                    return Err(io::Error::new(
                                        ErrorKind::Other,
                                        "Invalid domain name",
                                    ));
                                }
                            };
                            let port = ((buf[domain_len] as u16) << 8) +
                                buf[domain_len + 1] as u16;
                            Ok((socket, String::from(domain), port))
                        },
                    )
                })
                .and_then(move |(socket, domain, port)| {
                    info!("Resolving {}", &domain);
                    resolver.resolve(&domain).and_then(
                        move |mut addrs| match addrs
                            .pop() {
                            Some(addr) => Ok((socket, SocketAddr::new(addr, port))),
                            None => Err(io::Error::new(
                                ErrorKind::Other,
                                "Cannot resolve domain name",
                            )),
                        },
                    )
                }),
        ),
    });
    let reply = req.and_then(move |(socket, socket_addr)| {
        let target = redirect::Direct::new(socket_addr);
        // let target = redirect::Socks5::new("127.0.0.1:1086".parse().unwrap(), socket_addr);
        let connection = target.connect(handle.clone());
        connection.then(move |res| {
            info!("Connecting {}", socket_addr);
            let mut reply_data = vec![SOCKS5_VERSION, SUCCEEDED_REPLY, RESERVED_CODE];
            match socket_addr {
                SocketAddr::V4(addr) => {
                    let ip = addr.ip().octets();
                    let port = addr.port();
                    reply_data.extend_from_slice(
                        &[
                            AYTP::IPv4 as u8,
                            ip[0],
                            ip[1],
                            ip[2],
                            ip[3],
                            (port >> 8) as u8,
                            port as u8,
                        ],
                    )
                }
                SocketAddr::V6(addr) => {
                    let ip = addr.ip().octets();
                    let port = addr.port();
                    reply_data.extend_from_slice(
                        &[
                            AYTP::IPv6 as u8,
                            ip[0],
                            ip[1],
                            ip[2],
                            ip[3],
                            ip[4],
                            ip[5],
                            ip[6],
                            ip[7],
                            ip[8],
                            ip[9],
                            ip[10],
                            ip[11],
                            ip[12],
                            ip[13],
                            ip[14],
                            ip[15],
                            (port >> 8) as u8,
                            port as u8,
                        ],
                    );
                }
            };
            match res {
                Ok(conn) => {
                    non_send_box(write_all(socket, reply_data).and_then(|(socket, _)| {
                        Ok((socket, conn))
                    }))
                }
                Err(e) => {
                    info!("Error on connecting to remote server: {}", e);
                    reply_data[1] = GENERAL_SOCKS_SERVER_FAILURE_REPLY;
                    non_send_box(write_all(socket, reply_data).and_then(|_| {
                        Err(io::Error::new(ErrorKind::Other, "Connection failure"))
                    }))
                }
            }
        })
    });

    let passing = reply.and_then(|(socket, conn)| {
        info!("Ready for passing!");
        let socket = Rc::new(socket);
        let conn = Rc::new(conn);

        let client_to_server = Transfer::new(socket.clone(), conn.clone());
        let server_to_client = Transfer::new(conn, socket);

        client_to_server.join(server_to_client)
    });

    non_send_box(passing.then(move |res| {
        match res {
            Ok((outbound, inbound)) => {
                info!("Outbound: {} bytes, inbound: {} bytes", outbound, inbound);
            }
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
    buf: [u8; 4096],
    bytes_count: usize,
}

impl Transfer {
    fn new(reader: Rc<TcpStream>, writer: Rc<TcpStream>) -> Transfer {
        Transfer {
            reader: reader,
            writer: writer,
            buf: [0; 4096],
            bytes_count: 0,
        }
    }
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

            let read_n = try_nb!((&*self.reader).read(&mut self.buf));
            info!("Read {} bytes", read_n);
            if read_n == 0 {
                self.writer.shutdown(Shutdown::Write)?;
                return Ok(Async::Ready(self.bytes_count));
            }
            self.bytes_count += read_n;

            let write_n = (&*self.writer).write(&self.buf[..read_n])?;
            if read_n != write_n {
                return Err(io::Error::new(ErrorKind::Other, "Bad write"));
            }
        }
    }
}

fn non_send_box<F: Future + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error>> {
    Box::new(f)
}

