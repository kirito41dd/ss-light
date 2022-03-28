use std::fmt::Debug;

use ring::aead::AES_256_GCM;
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum CipherKind {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "aes-256-gcm")]
    AES_256_GCM,
}

impl CipherKind {
    pub fn iv_len(&self) -> usize {
        return match self {
            CipherKind::None => 0,
            CipherKind::AES_256_GCM => AES_256_GCM.nonce_len(),
        };
    }
    pub fn key_len(&self) -> usize {
        return match self {
            CipherKind::None => 0,
            CipherKind::AES_256_GCM => AES_256_GCM.key_len(),
        };
    }
    pub fn salt_len(&self) -> usize {
        return match self {
            CipherKind::None => 0,
            CipherKind::AES_256_GCM => 32,
        };
    }
    pub fn tag_len(&self) -> usize {
        return match self {
            CipherKind::None => 0,
            CipherKind::AES_256_GCM => AES_256_GCM.tag_len(),
        };
    }
    pub fn max_package_size(&self) -> usize {
        return match self {
            CipherKind::None => usize::MAX,
            CipherKind::AES_256_GCM => 0x3FFF,
        };
    }
}

impl Debug for CipherKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::AES_256_GCM => write!(f, "aes-256-gcm"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CipherKind;
    #[test]
    fn check_key_and_iv_len() {
        assert_eq!(CipherKind::None.key_len(), 0);
        assert_eq!(CipherKind::None.iv_len(), 0);
        assert_eq!(CipherKind::None.salt_len(), 0);

        assert_eq!(CipherKind::AES_256_GCM.key_len(), 32);
        assert_eq!(CipherKind::AES_256_GCM.iv_len(), 12);
        assert_eq!(CipherKind::AES_256_GCM.salt_len(), 32);
    }
}
