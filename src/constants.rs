pub mod socks {
    #[repr(u8)]
    #[derive(FromPrimitive, Debug, Clone, Copy)]
    pub enum AYTP {
        IPv4 = 0x01,
        IPv6 = 0x04,
        DomainName = 0x03,
    }

    pub const SOCKS5_VERSION: u8 = 0x05;

    pub const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
    pub const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

    pub const CONNECT_CMD: u8 = 0x01;

    pub const RESERVED_CODE: u8 = 0x00;

    pub const SUCCEEDED_REPLY: u8 = 0x00;
    pub const GENERAL_SOCKS_SERVER_FAILURE_REPLY: u8 = 0x01;
}
