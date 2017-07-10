use futures::Future;
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use std::io;

mod direct;
pub use self::direct::Direct;

mod socks5;
pub use self::socks5::Socks5;

pub trait Proxy {
    fn connect(&self, handle: Handle)
        -> Box<Future<Item = TcpStream, Error = io::Error> + 'static>;
}
