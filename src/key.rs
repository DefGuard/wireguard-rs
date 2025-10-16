//! Public key utilities

use std::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use base64::{DecodeError, Engine, prelude::BASE64_STANDARD};
#[cfg(feature = "serde")]
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Unexpected, Visitor},
};
use x25519_dalek::{PublicKey, StaticSecret};

const KEY_LENGTH: usize = 32;

/// Returns value of hex digit, if possible.
fn hex_value(char: u8) -> Option<u8> {
    match char {
        b'A'..=b'F' => Some(char - b'A' + 10),
        b'a'..=b'f' => Some(char - b'a' + 10),
        b'0'..=b'9' => Some(char - b'0'),
        _ => None,
    }
}

/// WireGuard key representation in binary form.
#[derive(Clone, Default)]
pub struct Key([u8; KEY_LENGTH]);

impl Key {
    /// Create a new key from buffer.
    #[must_use]
    pub fn new(buf: [u8; KEY_LENGTH]) -> Self {
        Self(buf)
    }

    #[must_use]
    pub fn as_array(&self) -> [u8; KEY_LENGTH] {
        self.0
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Converts `Key` to `String` of lower case hexadecimal digits.
    #[must_use]
    pub fn to_lower_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        let to_char = |nibble: u8| -> char {
            (match nibble {
                0..=9 => b'0' + nibble,
                _ => nibble + b'a' - 10,
            }) as char
        };
        self.0.iter().for_each(|byte| {
            hex.push(to_char(*byte >> 4));
            hex.push(to_char(*byte & 0xf));
        });
        hex
    }

    /// Converts a text string of hexadecimal digits to `Key`.
    ///
    /// # Errors
    /// Will return `DecodeError` if text string has wrong length,
    /// or contains an invalid character.
    pub fn decode<T: AsRef<[u8]>>(hex: T) -> Result<Self, DecodeError> {
        let hex = hex.as_ref();
        let length = hex.len();
        if length != KEY_LENGTH * 2 {
            return Err(DecodeError::InvalidLength(length));
        }

        let mut key = [0; KEY_LENGTH];
        for (index, chunk) in hex.chunks(2).enumerate() {
            let Some(msd) = hex_value(chunk[0]) else {
                return Err(DecodeError::InvalidByte(index, chunk[0]));
            };
            let Some(lsd) = hex_value(chunk[1]) else {
                return Err(DecodeError::InvalidByte(index, chunk[1]));
            };
            key[index] = msd << 4 | lsd;
        }
        Ok(Self(key))
    }

    /// Generate WireGuard private key.
    #[must_use]
    pub fn generate() -> Self {
        Self(StaticSecret::random().to_bytes())
    }

    /// Make WireGuard public key from a private key.
    #[must_use]
    pub fn public_key(&self) -> Self {
        let secret = StaticSecret::from(self.0);
        Self(PublicKey::from(&secret).to_bytes())
    }
}

impl TryFrom<&str> for Key {
    type Error = DecodeError;

    /// Try to decode `Key` from base16 or base64 encoded string.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == KEY_LENGTH * 2 {
            // Try base16
            Key::decode(value)
        } else {
            // Try base64
            let v = BASE64_STANDARD.decode(value)?;
            let length = v.len();
            if length == KEY_LENGTH {
                let buf = v
                    .try_into()
                    .map_err(|_| Self::Error::InvalidLength(length))?;
                Ok(Self::new(buf))
            } else {
                Err(Self::Error::InvalidLength(length))
            }
        }
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let length = value.len();
        if length == KEY_LENGTH {
            let buf = <[u8; KEY_LENGTH]>::try_from(value)
                .map_err(|_| Self::Error::InvalidLength(length))?;
            Ok(Self::new(buf))
        } else {
            Err(Self::Error::InvalidLength(length))
        }
    }
}

impl FromStr for Key {
    type Err = DecodeError;

    /// Try to decode `Key` from base16 or base64 encoded string.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.try_into()
    }
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Key {}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_lower_hex())
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

#[cfg(feature = "serde")]
impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(self.0))
    }
}

#[cfg(feature = "serde")]
struct KeyVisitor;

#[cfg(feature = "serde")]
impl Visitor<'_> for KeyVisitor {
    type Value = Key;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("32-bytes encoded as either base16 or base64")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Key::try_from(s).map_err(|_| serde::de::Error::invalid_value(Unexpected::Str(s), &self))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Key, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(KeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    use serde_test::{Token, assert_tokens};

    // Same `Key` in different representations.
    static KEY_B64: &str = "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=";
    static KEY_HEX: &str = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
    static KEY_BUF: [u8; KEY_LENGTH] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
        0x1e, 0x0f,
    ];

    #[test]
    fn decode_key() {
        let key = Key::decode(KEY_HEX).unwrap();
        assert_eq!(key.0, KEY_BUF);
        assert_eq!(key.to_lower_hex(), KEY_HEX);
        assert_eq!(key.to_string(), KEY_B64);
    }

    #[test]
    fn parse_key() {
        let key: Key = KEY_B64.try_into().unwrap();
        assert_eq!(key.0, KEY_BUF);
        assert_eq!(key.to_lower_hex(), KEY_HEX);
        assert_eq!(key.to_string(), KEY_B64);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_key() {
        let key = Key(KEY_BUF);
        assert_tokens(&key, &[Token::Str(KEY_B64)]);
    }
}
