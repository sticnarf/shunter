use futures::{self, Future};

pub trait FutureExt<F: Future> {
    fn into_box(self) -> Box<Future<Item=F::Item, Error=F::Error>>;
}

impl<F: Future + 'static> FutureExt<F> for F {
    fn into_box(self) -> Box<Future<Item=F::Item, Error=F::Error>> {
        Box::new(self)
    }
}

#[macro_export]
macro_rules! tokio_err {
    ($msg:expr) => ({
        use std::io::{self, ErrorKind};
        Err(io::Error::new(ErrorKind::Other, $msg))
    });
}

// Only SOCKS version 5 is supported
#[macro_export]
macro_rules! check_socks_version {
    ($v:expr) => {
        if $v != SOCKS5_VERSION {
            return tokio_err!("Unsupported SOCKS version");
        }
    };
}