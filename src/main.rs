extern crate futures;
extern crate tokio_io;
extern crate tokio_proto;
extern crate tokio_service;
extern crate tokio_core;
extern crate bytes;
extern crate num;
#[macro_use]
extern crate num_derive;

use tokio_proto::TcpServer;

mod protocol;

fn main() {
    // let addr = "0.0.0.0:12345"
    //     .parse()
    //     .expect("Parse binding address error");

    // let server = TcpServer::new(protocol::SocksProto, addr);

    // server.serve(|| Ok(protocol::Proxy));
}

