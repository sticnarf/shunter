use redirect::Proxy;
use futures::Future;
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use tokio_io::io::{write_all, read_exact};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use num::FromPrimitive;
use constants::socks::*;
use socks_helpers::FutureExt;

pub struct Socks5 {
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl Socks5 {
    pub fn new(proxy_addr: SocketAddr, target_addr: SocketAddr) -> Socks5 {
        Socks5 {
            proxy_addr: proxy_addr,
            target_addr: target_addr,
        }
    }
}

impl Proxy for Socks5 {
    fn connect(
        &self,
        handle: Handle,
    ) -> Box<Future<Item=TcpStream, Error=io::Error> + 'static> {
        let connect = TcpStream::connect(&self.proxy_addr, &handle).and_then(|conn| {
            write_all(conn, [SOCKS5_VERSION, 1, NO_AUTHENTICATION_REQUIRED]).map(|(conn, _)| conn)
        });

        let auth_ok = connect.and_then(|conn| {
            read_exact(conn, [0u8; 2]).and_then(|(conn, buf)| {
                check_socks_version!(buf[0]);
                if buf[1] != NO_AUTHENTICATION_REQUIRED {
                    return tokio_err!("No acceptable authentication methods");
                }
                Ok(conn)
            })
        });

        let target_addr = self.target_addr.clone();
        let req = auth_ok.and_then(move |conn| {
            let mut msg = vec![SOCKS5_VERSION, CONNECT_CMD, RESERVED_CODE];
            match target_addr.clone() {
                SocketAddr::V4(addr) => {
                    msg.push(AYTP::IPv4 as u8);
                    msg.extend(&addr.ip().octets());
                }
                SocketAddr::V6(addr) => {
                    msg.push(AYTP::IPv6 as u8);
                    msg.extend(&addr.ip().octets());
                }
            }
            let port = target_addr.port();
            msg.push((port >> 8) as u8);
            msg.push(port as u8);
            write_all(conn, msg).map(|(conn, _)| conn)
        });

        let ack = req.and_then(|conn| {
            read_exact(conn, [0u8; 4])
                .and_then(|(conn, buf)| {
                    if buf[0] != SOCKS5_VERSION {
                        return tokio_err!("Unsupported SOCKS version");
                    }
                    if buf[1] != SUCCEEDED_REPLY {
                        return tokio_err!("Request not succeeded");
                    }
                    if buf[2] != RESERVED_CODE {
                        return tokio_err!(format!("Expect reserved code, but {}", buf[2]));
                    }
                    match FromPrimitive::from_u8(buf[3]) {
                        Some(aytp) => Ok((conn, aytp)),
                        None => tokio_err!("Unknown AYTP"),
                    }
                })
                .and_then(|(conn, aytp)| match aytp {
                    AYTP::IPv4 => {
                        read_exact(conn, [0u8; 6])
                            .and_then(|(conn, _)| Ok(conn))
                            .into_box()
                    }
                    AYTP::IPv6 => {
                        read_exact(conn, [0u8; 18])
                            .and_then(|(conn, _)| Ok(conn))
                            .into_box()
                    }
                    AYTP::DomainName => {
                        read_exact(conn, [0u8])
                            .map(|(conn, buf)| (conn, buf[0]))
                            .and_then(|(conn, domain_len)| {
                                read_exact(conn, vec![0u8; (domain_len as usize) + 2]).map(
                                    |(conn, _)| conn,
                                )
                            })
                            .into_box()
                    }
                })
        });

        ack.into_box()
    }
}
