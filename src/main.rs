extern crate futures;
extern crate tokio_io;
extern crate tokio_proto;
extern crate tokio_service;
extern crate tokio_core;
extern crate bytes;
extern crate num;
extern crate trust_dns;
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate log;
extern crate env_logger;

use tokio_proto::TcpServer;

mod protocol;

fn main() {
    env_logger::init().expect("env_logger failed to start");

    let addr = "0.0.0.0:12345"
        .parse()
        .expect("Parse binding address error");

    let server = TcpServer::new(protocol::SocksProto, addr);

    server.serve(|| Ok(protocol::LocalRedirect::new()));
}
