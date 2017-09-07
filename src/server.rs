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
use socks_helpers::FutureExt;

pub fn serve(
    socket: TcpStream,
    peer_address: SocketAddr,
    handle: Handle,
    resolver: CpuPoolResolver,
) -> Box<Future<Item=(), Error=io::Error>> {
    // Read the SOCKS version and the number of methods the client supports
    let auth = read_exact(socket, [0u8; 2]).and_then(|(socket, buf)| {
        check_socks_version!(buf[0]);
        Ok((socket, buf[1]))
    }).and_then(|(socket, method_cnt)|
        // Read the acceptable methods
        read_exact(socket, vec![0u8; method_cnt as usize]).and_then(|(socket, buf)|
            // No authentication method is supported at this stage
            if buf.iter().any(|&x| x == NO_AUTHENTICATION_REQUIRED) {
                // Tell the client that we do not use authentication
                write_all(socket, [SOCKS5_VERSION, NO_AUTHENTICATION_REQUIRED])
                    .map(|(socket, _)| socket).into_box()
            } else {
                write_all(socket, [SOCKS5_VERSION, NO_ACCEPTABLE_METHODS])
                    .and_then(|_| tokio_err!("No acceptable authentication methods")).into_box()
            })
    );

    let req = auth.and_then(|socket|
        read_exact(socket, [0u8; 4]).and_then(|(socket, buf)| {
            check_socks_version!(buf[0]);

            // TODO Only support CONNECT command at this stage
            if buf[1] != CONNECT_CMD {
                return tokio_err!("Unsupported command");
            }

            // RSV must be zero
            if buf[2] != RESERVED_CODE {
                return tokio_err!(format!("Expect reserved code, but {}", buf[2]));
            }

            match FromPrimitive::from_u8(buf[3]) {
                Some(aytp) => {
                    debug!("AYTP: {:?}", aytp);
                    Ok((socket, aytp))
                }
                None => tokio_err!("Unknown AYTP"),
            }
        })
    ).and_then(move |(socket, aytp)|
        match aytp {
            AYTP::IPv4 => read_exact(socket, [0u8; 6])
                .map(|(socket, buf)| (socket, buf.extract_addr())).into_box(),
            AYTP::IPv6 => read_exact(socket, [0u8; 18])
                .map(|(socket, buf)| (socket, buf.extract_addr())).into_box(),
            AYTP::DomainName =>
                read_exact(socket, [0u8]).and_then(|(socket, buf)| {
                    let domain_len = buf[0] as usize; // Get domain length first
                    read_exact(socket, vec![0u8; domain_len + 2]).and_then(move |(socket, buf)| {
                        let domain = match str::from_utf8(&buf[..domain_len]) {
                            Ok(domain) => domain,
                            Err(_) => return tokio_err!("Invalid domain name")
                        };
                        let port = ((buf[domain_len] as u16) << 8) + buf[domain_len + 1] as u16;
                        Ok((socket, String::from(domain), port))
                    })
                }).and_then(move |(socket, domain, port)| {
                    // TODO move to trust-dns in the future
                    debug!("Resolving {}", &domain);
                    resolver.resolve(&domain).and_then(move |mut addr_list|
                        match addr_list.pop() {
                            Some(addr) => Ok((socket, SocketAddr::new(addr, port))),
                            None => tokio_err!("Cannot resolve domain name"),
                        }
                    )
                }).into_box(),
        }
    );

    let reply = req.and_then(move |(socket, target_addr)| {
        // TODO switch redirecting method by rules
        let target = redirect::Direct::new(target_addr);
        // let target = redirect::Socks5::new("127.0.0.1:1086".parse().unwrap(), target_addr);
        let connection = target.connect(handle.clone());
        connection.then(move |res| {
            debug!("Connecting {}", target_addr);
            let mut reply_data = vec![SOCKS5_VERSION, SUCCEEDED_REPLY, RESERVED_CODE];
            match target_addr {
                SocketAddr::V4(addr) => {
                    let ip = addr.ip().octets();
                    let port = addr.port();
                    reply_data.extend_from_slice(&[
                        AYTP::IPv4 as u8,
                        ip[0], ip[1], ip[2], ip[3],
                        (port >> 8) as u8, port as u8,
                    ]);
                }
                SocketAddr::V6(addr) => {
                    let ip = addr.ip().octets();
                    let port = addr.port();
                    reply_data.extend_from_slice(&[
                        AYTP::IPv6 as u8,
                        ip[0], ip[1], ip[2], ip[3],
                        ip[4], ip[5], ip[6], ip[7],
                        ip[8], ip[9], ip[10], ip[11],
                        ip[12], ip[13], ip[14], ip[15],
                        (port >> 8) as u8, port as u8,
                    ]);
                }
            };

            match res {
                Ok(conn) => {
                    write_all(socket, reply_data)
                        .map(|(socket, _)| (socket, conn)).into_box()
                }
                Err(e) => {
                    debug!("Error on connecting to remote server: {}", e);
                    reply_data[1] = GENERAL_SOCKS_SERVER_FAILURE_REPLY;
                    write_all(socket, reply_data)
                        .and_then(|_| tokio_err!("Connecting to target server failure")).into_box()
                }
            }
        })
    });

    let passing = reply.and_then(|(socket, conn)| {
        debug!("Ready for passing!");
        let socket = Rc::new(socket);
        let conn = Rc::new(conn);

        let client_to_server = Transfer::new(socket.clone(), conn.clone());
        let server_to_client = Transfer::new(conn, socket);

        client_to_server.join(server_to_client)
    });

    passing.then(move |res| {
        match res {
            Ok((outbound, inbound)) => {
                debug!("Outbound: {} bytes, inbound: {} bytes", outbound, inbound);
            }
            Err(e) => {
                error!("Error with client {}: {}", peer_address, e);
            }
        }
        Ok(())
    }).into_box()
}

struct Transfer {
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,
    buf: Vec<u8>,
    read_n: usize,
    write_p: usize,
    bytes_count: usize,
}

impl Transfer {
    fn new(reader: Rc<TcpStream>, writer: Rc<TcpStream>) -> Transfer {
        Transfer {
            reader: reader,
            writer: writer,
            buf: vec![0; 65536],
            read_n: 0,
            write_p: 0,
            bytes_count: 0,
        }
    }
}

impl Future for Transfer {
    type Item = usize;
    type Error = io::Error;
    
    fn poll(&mut self) -> Poll<usize, io::Error> {
        loop {
            while self.read_n > 0 {
                let write_ready = self.writer.poll_write().is_ready();
                if !write_ready {
                    return Ok(Async::NotReady);
                }

                let write_n = try_nb!((&*self.writer).write(&self.buf[self.write_p..self.read_n]));
                debug!("Write {} bytes", write_n);
                self.write_p += write_n;

                if self.write_p == self.read_n {
                    self.read_n = 0;
                }
            }

            let read_ready = self.reader.poll_read().is_ready();
            let write_ready = self.writer.poll_write().is_ready();
            if !(read_ready && write_ready) {
                return Ok(Async::NotReady);
            }

            self.read_n = try_nb!((&*self.reader).read(&mut self.buf[..]));
            if self.read_n == 0 {
                self.writer.shutdown(Shutdown::Write)?;
                return Ok(Async::Ready(self.bytes_count));
            }
            self.bytes_count += self.read_n;
            self.write_p = 0;
            debug!("Read {} bytes", self.read_n);

            let write_n = try_nb!((&*self.writer).write(&self.buf[self.write_p..self.read_n]));
            debug!("Write {} bytes", write_n);
            self.write_p += write_n;

            if self.write_p == self.read_n {
                self.read_n = 0;
            }
        }
    }
}

trait BinaryAddress {
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