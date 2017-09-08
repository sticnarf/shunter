use futures::Future;
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use std::io;

mod direct;

pub use self::direct::Direct;

mod socks;

pub use self::socks::Socks5;

pub trait Proxy {
    fn connect(&self, handle: Handle)
               -> Box<Future<Item=TcpStream, Error=io::Error> + 'static>;
}