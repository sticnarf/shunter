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

use tokio_proto::TcpServer;
use tokio_core::reactor::Core;
use trust_dns::udp::UdpClientStream;
use trust_dns::client::ClientFuture;

mod protocol;

fn main() {


    let addr = "0.0.0.0:12345"
        .parse()
        .expect("Parse binding address error");

    let server = TcpServer::new(protocol::SocksProto, addr);

    server.serve(|| {
        let ev_loop = Core::new().expect("Unable to create an event loop");

        // Default DNS server
        let dns_addr = "192.168.1.1:53"
            .parse()
            .expect("Parse dns address error");
        let (stream, sender) = UdpClientStream::new(dns_addr, ev_loop.handle());
        let dns_client = ClientFuture::new(stream, sender, ev_loop.handle(), None);

        Ok(protocol::LocalRedirect {
               ev_handle: ev_loop.handle(),
               dns_client: dns_client,
           })
    });
}

