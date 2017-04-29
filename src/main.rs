extern crate tokio_proto;

mod protocol;

use tokio_proto::TcpServer;

fn main() {
    let addr = "0.0.0.0:12345".parse().unwrap();

    let server = TcpServer::new(protocol::SocksProto, addr);

    server.serve(|| Ok(protocol::Proxy));
}
