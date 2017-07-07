extern crate futures;
extern crate tokio_core;
#[macro_use]
extern crate tokio_io;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate num;
#[macro_use]
extern crate num_derive;
extern crate clap;
extern crate tokio_dns;

use futures::{future, Future, Stream};
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;
use tokio_dns::CpuPoolResolver;
use std::str;
use clap::{Arg, App};

mod socks;

fn main() {
    let matches = App::new("shunter")
        .version("0.1")
        .author("Yilin Chen <sticnarf@gmail.com>")
        .about(
            "Redirect your SOCKS5 traffic to different servers under custom rules",
        )
        .arg(
            Arg::with_name("binding")
                .short("b")
                .long("binding")
                .value_name("IP")
                .default_value("0.0.0.0")
                .help("Bind shunter to the specific IP")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .default_value("1080")
                .help("Run shunter on the specific port")
                .takes_value(true),
        )
        .get_matches();

    drop(env_logger::init().unwrap());

    let mut core = Core::new().expect("Unable to create reactor");
    let handle = core.handle();

    let address = format!(
        "{}:{}",
        matches.value_of("binding").unwrap(),
        matches.value_of("port").unwrap()
    ).parse()
        .expect("Invalid binding IP or port");

    let listener = TcpListener::bind(&address, &handle).expect(&format!(
        "Unable to bind to address: {}",
        address
    ));

    let connections = listener.incoming();
    let resolver = CpuPoolResolver::new(1);
    let server = connections.for_each(|(socket, peer_address)| {
        info!("Listen to client: {}", peer_address);
        handle.spawn(
            socks::serve(socket, peer_address, handle.clone(), resolver.clone())
                .then(|_| future::ok(())),
        );
        Ok(())
    });
    core.run(server).ok();
}
