extern crate clap;
extern crate futures;
extern crate num;
extern crate num_cpus;
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate slog;
extern crate slog_async;
#[macro_use]
extern crate slog_scope;
extern crate slog_term;
extern crate tokio_core;
extern crate tokio_dns;
#[macro_use]
extern crate tokio_io;

#[macro_use]
mod socks;
pub mod redirect;

use std::net::SocketAddr;
use std::str;
use futures::{future, Async, Future, Poll, Stream};
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_io::io::{read_exact, write_all};
use tokio_dns::{CpuPoolResolver, Resolver};
use std::net::Shutdown;
use std::io::{self, Read, Write};
use std::rc::Rc;
use std::cell::RefCell;
use std::marker::PhantomData;
use num::FromPrimitive;
use redirect::Proxy;
use socks::*;

pub struct Shunter<R>
where
    R: Router + 'static,
{
    ev_loop: Core,
    listener: TcpListener,
    phantom_router: PhantomData<R>,
}

impl<R> Shunter<R>
where
    R: Router + 'static,
{
    pub fn create(bind_addr: SocketAddr) -> io::Result<Shunter<R>> {
        let ev_loop = Core::new()?;
        let listener = TcpListener::bind(&bind_addr, &ev_loop.handle())?;
        Ok(Shunter {
            ev_loop,
            listener,
            phantom_router: PhantomData,
        })
    }

    pub fn start(self, router: R) {
        let connections = self.listener.incoming();
        let resolver = CpuPoolResolver::new(num_cpus::get());
        let handle = self.ev_loop.handle();
        let router = Rc::new(RefCell::new(router));
        let mut ev_loop = self.ev_loop;
        let server = connections
            .for_each(move |(socket, peer_addr)| {
                info!("Start listening to client: {}", peer_addr);
                handle.spawn(
                    Shunter::serve(
                        socket,
                        peer_addr,
                        handle.clone(),
                        resolver.clone(),
                        router.clone(),
                    ).then(|_| Ok(())),
                );
                Ok(())
            })
            .into_box();
        ev_loop.run(server).ok();
    }

    fn serve(
        socket: TcpStream,
        peer_address: SocketAddr,
        handle: Handle,
        resolver: CpuPoolResolver,
        router: Rc<RefCell<R>>,
    ) -> Box<Future<Item = (), Error = io::Error> + 'static> {
        // Read the SOCKS version and the number of methods the client supports
        let auth = read_exact(socket, [0u8; 2])
            .and_then(|(socket, buf)| {
                check_socks_version!(buf[0]);
                Ok((socket, buf[1]))
            })
            .and_then(|(socket, method_cnt)|
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
            }));

        let req = auth.and_then(|socket| {
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
        }).and_then(move |(socket, aytp)| match aytp {
                AYTP::IPv4 => read_exact(socket, [0u8; 6])
                    .map(|(socket, buf)| (socket, buf.extract_addr()))
                    .into_box(),
                AYTP::IPv6 => read_exact(socket, [0u8; 18])
                    .map(|(socket, buf)| (socket, buf.extract_addr()))
                    .into_box(),
                AYTP::DomainName => read_exact(socket, [0u8])
                    .and_then(|(socket, buf)| {
                        let domain_len = buf[0] as usize; // Get domain length first
                        read_exact(socket, vec![0u8; domain_len + 2]).and_then(
                            move |(socket, buf)| {
                                let domain = match str::from_utf8(&buf[..domain_len]) {
                                    Ok(domain) => domain,
                                    Err(_) => return tokio_err!("Invalid domain name"),
                                };
                                let port =
                                    ((buf[domain_len] as u16) << 8) + buf[domain_len + 1] as u16;
                                Ok((socket, String::from(domain), port))
                            },
                        )
                    })
                    .and_then(move |(socket, domain, port)| {
                        // TODO move to trust-dns in the future
                        debug!("Resolving {}", &domain);
                        resolver.resolve(&domain).and_then(
                            move |mut addr_list| match addr_list.pop() {
                                Some(addr) => Ok((socket, SocketAddr::new(addr, port))),
                                None => tokio_err!("Cannot resolve domain name"),
                            },
                        )
                    })
                    .into_box(),
            });

        let reply = req.and_then(move |(socket, target_addr)| {
            let client_addr = match socket.peer_addr() {
                Ok(addr) => addr,
                Err(e) => return future::err(e).into_box(),
            };
            let proxy = router.borrow().route(client_addr, target_addr);
            let connection = proxy.connect(handle.clone());
            connection
                .then(move |res| {
                    debug!("Connecting {}", target_addr);
                    let mut reply_data = vec![SOCKS5_VERSION, SUCCEEDED_REPLY, RESERVED_CODE];
                    match target_addr {
                        SocketAddr::V4(addr) => {
                            let ip = addr.ip().octets();
                            let port = addr.port();
                            reply_data.extend_from_slice(&[
                                AYTP::IPv4 as u8,
                                ip[0],
                                ip[1],
                                ip[2],
                                ip[3],
                                (port >> 8) as u8,
                                port as u8,
                            ]);
                        }
                        SocketAddr::V6(addr) => {
                            let ip = addr.ip().octets();
                            let port = addr.port();
                            reply_data.extend_from_slice(&[
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
                            ]);
                        }
                    };

                    match res {
                        Ok(conn) => write_all(socket, reply_data)
                            .map(|(socket, _)| (socket, conn))
                            .into_box(),
                        Err(e) => {
                            debug!("Error on connecting to remote server: {}", e);
                            reply_data[1] = GENERAL_SOCKS_SERVER_FAILURE_REPLY;
                            write_all(socket, reply_data)
                                .and_then(|_| tokio_err!("Connecting to target server failure"))
                                .into_box()
                        }
                    }
                })
                .into_box()
        });

        let passing = reply.and_then(|(socket, conn)| {
            debug!("Ready for passing!");
            let socket = Rc::new(socket);
            let conn = Rc::new(conn);

            let client_to_server = Transfer::new(socket.clone(), conn.clone());
            let server_to_client = Transfer::new(conn, socket);

            client_to_server.join(server_to_client)
        });

        passing
            .then(move |res| {
                match res {
                    Ok((_, _)) => {
                        info!("Connection with client {} completed.", peer_address);
                    }
                    Err(e) => {
                        error!("Error with client {}: {}", peer_address, e);
                    }
                }
                Ok(())
            })
            .into_box()
    }
}

pub trait Router {
    fn route(&self, from: SocketAddr, to: SocketAddr) -> Box<Proxy>;
}

struct Transfer {
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,
    buf: Vec<u8>,
    read_n: usize,
    write_p: usize,
}

impl Transfer {
    fn new(reader: Rc<TcpStream>, writer: Rc<TcpStream>) -> Transfer {
        Transfer {
            reader,
            writer,
            buf: vec![0; 4096],
            read_n: 0,
            write_p: 0,
        }
    }
}

impl Future for Transfer {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            let read_ready = self.reader.poll_read().is_ready();
            let write_ready = self.writer.poll_write().is_ready();

            // Writer must be ready.
            // And either there are some bytes in the buffer not sent yet or reader is ready.
            if !write_ready || (self.read_n == 0 && !read_ready) {
                return Ok(Async::NotReady);
            }

            // There are no data in the buffer. Must read from reader.
            if self.read_n == 0 {
                self.read_n = try_nb!((&*self.reader).read(&mut self.buf[..]));

                // self.read_n == 0 indicates EOF
                if self.read_n == 0 {
                    self.writer.shutdown(Shutdown::Write)?;
                    return Ok(Async::Ready(()));
                }

                // Read successfully. Reset write pointer.
                self.write_p = 0;
                debug!("Read {} bytes", self.read_n);
            }

            let write_n = try_nb!((&*self.writer).write(&self.buf[self.write_p..self.read_n]));
            self.write_p += write_n;
            debug!("Write {} bytes", write_n);

            // Have written all bytes in the buffer, clear read_n
            if self.write_p == self.read_n {
                self.read_n = 0;
            }
        }
    }
}
