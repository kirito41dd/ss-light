mod consts;
pub use self::consts::Error;
pub mod crypto;
pub use crypto::kind::CipherKind;
mod handshake;
pub use self::handshake::Address;
pub mod util;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
