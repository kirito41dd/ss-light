use bytes::{BufMut, Bytes, BytesMut};
use rand::Fill;
use ring::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};

use crate::{util, CipherKind, Error};

/// An AEAD encrypted UDP packet has the following structure
///
/// [salt][encrypted payload][tag]
pub struct PacketCipher {
    kind: CipherKind,
    key: Bytes,
}

impl PacketCipher {
    pub fn new(kind: CipherKind, key: &[u8]) -> Self {
        match kind {
            CipherKind::AES_256_GCM => Self {
                kind,
                key: Bytes::copy_from_slice(key),
            },
            _ => panic!("unsupport chipher kind"),
        }
    }

    pub fn encrypt_to(&self, buf: &[u8]) -> Result<BytesMut, Error> {
        self.encrypt_vec_slice_to(vec![buf])
    }

    pub fn encrypt_vec_slice_to(&self, v: Vec<&[u8]>) -> Result<BytesMut, Error> {
        let mut send_buf = BytesMut::with_capacity(self.kind.salt_len());
        unsafe { send_buf.advance_mut(self.kind.salt_len()) }
        send_buf.try_fill(&mut rand::thread_rng()).unwrap();

        let sub_key = util::hkdf_sha1(&self.key, &send_buf);
        let unbound =
            UnboundKey::new(&AES_256_GCM, &sub_key).expect("key.len != algorithm.key_len");
        let mut sealing_key = SealingKey::new(unbound, util::NonceZeroSequence {});

        for d in v {
            send_buf.extend_from_slice(d);
        }

        let tag = sealing_key
            .seal_in_place_separate_tag(
                Aad::<[u8; 0]>::empty(),
                &mut send_buf.as_mut()[self.kind.salt_len()..],
            )
            .map_err(Error::CipherError)?;

        send_buf.extend_from_slice(tag.as_ref());

        Ok(send_buf)
    }

    pub fn decrypt_from(&self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.len() <= self.kind.salt_len() + self.kind.tag_len() {
            return Err(Error::InvalidPackage);
        }
        let salt = &buf[..self.kind.salt_len()];
        let sub_key = util::hkdf_sha1(&self.key, salt);

        let unbound =
            UnboundKey::new(&AES_256_GCM, &sub_key).expect("key.len != algorithm.key_len");
        let mut opening_key = OpeningKey::new(unbound, util::NonceZeroSequence {});

        let data = opening_key
            .open_in_place(Aad::<[u8; 0]>::empty(), &mut buf[self.kind.salt_len()..])
            .map_err(Error::CipherError)?;

        let data_len = data.len();
        for i in 0..data_len {
            buf[i] = buf[i + self.kind.salt_len()]
        }

        Ok(data_len)
    }
}

#[cfg(test)]
mod tests {

    use crate::{util, CipherKind};

    use super::PacketCipher;

    #[tokio::test]
    async fn test_packet() {
        let pwd = "123456";
        let kind = CipherKind::AES_256_GCM;
        let key = util::evp_bytes_to_key(pwd.as_bytes(), kind.key_len());
        let packet = PacketCipher::new(kind, &key);

        let data = &b"hello world!"[..];

        let mut m = packet.encrypt_to(data).unwrap();

        assert_eq!(m.len(), kind.salt_len() + kind.tag_len() + data.len());

        let d = packet.decrypt_from(&mut m).unwrap();

        assert_eq!(data, &m[..d])
    }
}
