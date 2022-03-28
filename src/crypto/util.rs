use md5::{Digest, Md5};
use ring::aead::{Nonce, NONCE_LEN};
use ring::hkdf::{KeyType, Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY};

/// NonceSequence implemented according to [shadowsocks wiki](https://shadowsocks.org/en/wiki/AEAD-Ciphers.html).
/// the nonce is incremented by one as if it were an unsigned little-endian integer
pub struct NonceSequence {
    nonce: [u8; NONCE_LEN],
    is_first: bool,
}

impl NonceSequence {
    pub fn new() -> Self {
        NonceSequence {
            nonce: [0u8; NONCE_LEN],
            is_first: true,
        }
    }

    /// return nonce after adding one, it were an unsigned little-endian integer
    pub fn increment(&mut self) -> &[u8] {
        if self.is_first {
            self.is_first = false;
            return &self.nonce;
        }

        for i in 0..self.nonce.len() {
            if self.nonce[i] < 0xff {
                self.nonce[i] += 1;
                break;
            } else {
                self.nonce[i] = 0;
            }
        }
        return &self.nonce;
    }
}

/// For ring aead
impl ring::aead::NonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        Nonce::try_assume_unique_for_key(self.increment())
    }
}

pub fn hkdf_sha1(key: &[u8], salt: &[u8]) -> Vec<u8> {
    const SUBKEY_INFO: &'static [u8] = b"ss-subkey";
    let mut sub_key = Vec::<u8>::from([0u8; 64]);

    struct CryptoKeyType(usize);
    impl KeyType for CryptoKeyType {
        fn len(&self) -> usize {
            self.0
        }
    }

    let s = Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = s.extract(key);
    let okm = prk
        .expand(&[SUBKEY_INFO], CryptoKeyType(key.len()))
        .expect("hkdf_sha1_expand");
    sub_key.truncate(key.len());
    okm.fill(&mut sub_key).expect("hkdf_sha1_fill");

    sub_key
}

pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Box<[u8]> {
    let mut key = vec![0u8; key_len];
    let mut last = None;
    let mut offset = 0usize;
    while offset < key_len {
        let mut m = Md5::new();

        if let Some(digest) = last {
            m.update(&digest);
        }

        m.update(password);

        let digest = m.finalize();

        let amt = std::cmp::min(key_len - offset, digest.len());
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);

        offset += amt;
        last = Some(digest);
    }

    key.into_boxed_slice()
}

#[cfg(test)]
mod tests {

    use super::{evp_bytes_to_key, hkdf_sha1, NonceSequence};
    #[test]
    fn test_nonce_increment() {
        let mut seq = NonceSequence::new();
        for i in 0..=255 {
            assert_eq!(seq.increment(), [i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        }
        for i in 0..=255 {
            assert_eq!(seq.increment(), [i, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        }
    }

    #[test]
    fn test_hkdf_sha1() {
        let sub_key = hkdf_sha1(&[0u8; 16], &[0u8; 32]);
        println!("{:?}", sub_key)
    }

    #[test]
    fn test_evp_bytes_to_key() {
        let key = evp_bytes_to_key(b"foobar", 32);
        assert_eq!(
            &key[..],
            &[
                0x38u8, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43,
                0x12, 0xc6, 0x3f, 0x56, 0x83, 0x78, 0x52, 0x96, 0x14, 0xd2, 0x2d, 0xdb, 0x49, 0x23,
                0x7d, 0x2f, 0x60, 0xbf, 0xdf
            ]
        )
    }
}
