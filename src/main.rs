extern crate futures;
extern crate tokio_core;
#[macro_use]
extern crate tokio_io;
extern crate num;
#[macro_use]
extern crate num_derive;
extern crate clap;
extern crate tokio_dns;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;
#[macro_use]
extern crate slog_scope;

use std::net::SocketAddr;
use futures::{future, Future, Stream};
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;
use tokio_dns::CpuPoolResolver;
use std::str;
use clap::{Arg, App};

#[macro_use]
mod socks_helpers;
mod server;
mod redirect;
mod constants;

fn main() {
    let config = clap();

    let _log_guard = init_logger(&config);

    let mut core = Core::new().expect("Unable to create reactor");
    let handle = core.handle();

    let listener = TcpListener::bind(&config.addr, &handle).expect(&format!(
        "Unable to bind to address: {}", &config.addr
    ));

    let connections = listener.incoming();
    let resolver = CpuPoolResolver::new(1);
    let server = connections.for_each(|(socket, peer_addr)| {
        info!("Start listening to client: {}", peer_addr);
        handle.spawn(
            server::serve(socket, peer_addr, handle.clone(), resolver.clone())
                .then(|_| Ok(())),
        );
        Ok(())
    });
    core.run(server).ok();
}

struct Config {
    addr: SocketAddr,
}

/// Parse configs from the command line arguments.
fn clap() -> Config {
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

    // Panic the program if an invalid binding address is given
    let addr = format!("{}:{}",
                       matches.value_of("binding").unwrap(),
                       matches.value_of("port").unwrap()).parse()
        .expect("Invalid binding IP or port");

    Config {
        addr: addr
    }
}

/// Initial the slog logger.
/// This function returns a `GlobalLoggerGuard` which should be well saved.
/// After the `GlobalLoggerGuard` is dropped, the global logger will be unavailable.
fn init_logger(config: &Config) -> slog_scope::GlobalLoggerGuard {
    use slog::Drain;

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, o!());
    slog_scope::set_global_logger(log)
}