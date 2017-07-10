use futures::Future;
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use std::io;

mod direct;
pub use self::direct::Direct;

pub trait Target {
    fn connect(&self, handle: Handle)
        -> Box<Future<Item = TcpStream, Error = io::Error> + 'static>;
}
