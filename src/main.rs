extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
#[macro_use]
extern crate log;
extern crate env_logger;

use futures::{Stream, Future, BoxFuture, future};
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_io::io::{read_exact, write_all};
use std::net::SocketAddr;
use std::str;
use std::io;
use std::io::ErrorKind;

fn main() {
    drop(env_logger::init().unwrap());

    let mut core = Core::new().expect("Unable to create reactor");
    let handle = core.handle();

    let address = "0.0.0.0:12345".parse().unwrap();
    let listener = TcpListener::bind(&address, &handle).expect(&format!("Unable to bind to address: {}", address));

    let connections = listener.incoming();
    let server = connections.for_each(|(socket, peer_address)| {
        info!("Listen to client: {}", peer_address);
        serve(socket, peer_address)
    });
    core.run(server).ok();
}

fn serve(socket: TcpStream, peer_address: SocketAddr) -> BoxFuture<(), io::Error> {
    let syn = read_exact(socket, [0u8; 2]).and_then(|(socket, buf)| {
        if buf[0] != SOCKS5_VERSION {
            return Err(io::Error::new(ErrorKind::Other, "Unsupported SOCKS version"));
        }
        Ok((socket, buf[1]))
    }).and_then(|(socket, method_cnt)| {
        read_exact(socket, vec![0u8; method_cnt as usize]).and_then(|(socket, buf)| {
            if buf.iter().any(|&x| x == NO_AUTHENTICATION_REQUIRED) {
                write_all(socket, [SOCKS5_VERSION, NO_AUTHENTICATION_REQUIRED]).and_then(|(socket, _)| Ok(socket)).boxed()
            } else {
                write_all(socket, [SOCKS5_VERSION, NO_ACCEPTABLE_METHODS]).and_then(|_| Err(io::Error::new(ErrorKind::Other, "Unsupported SOCKS version"))).boxed()
            }
        })
    });
    syn.then(move |res| {
        if let Err(e) = res {
            info!("Error with client {}: {}", peer_address, e);
        }
        Ok(())
    }).boxed()
}

const SOCKS5_VERSION: u8 = 0x05;

const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;