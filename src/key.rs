//! Public key utilities

use std::{
    error, fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use base64::{prelude::BASE64_STANDARD, DecodeError, Engine};
use serde::{Deserialize, Serialize};

const KEY_LENGTH: usize = 32;

/// WireGuard key representation in binary form.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Key([u8; KEY_LENGTH]);

#[derive(Debug)]
pub enum KeyError {
    InvalidCharacter(u8),
    InvalidStringLength(usize),
}

impl error::Error for KeyError {}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidCharacter(char) => {
                write!(f, "Invalid character {char}")
            }
            Self::InvalidStringLength(length) => write!(f, "Invalid string length {length}"),
        }
    }
}

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
    /// Will return `KeyError` if text string has wrong length,
    /// or contains an invalid character.
    pub fn decode<T: AsRef<[u8]>>(hex: T) -> Result<Self, KeyError> {
        let hex = hex.as_ref();
        let length = hex.len();
        if length != 64 {
            return Err(KeyError::InvalidStringLength(length));
        }

        let hex_value = |char: u8| -> Result<u8, KeyError> {
            match char {
                b'A'..=b'F' => Ok(char - b'A' + 10),
                b'a'..=b'f' => Ok(char - b'a' + 10),
                b'0'..=b'9' => Ok(char - b'0'),
                _ => Err(KeyError::InvalidCharacter(char)),
            }
        };

        let mut key = [0; KEY_LENGTH];
        for (index, chunk) in hex.chunks(2).enumerate() {
            let msd = hex_value(chunk[0])?;
            let lsd = hex_value(chunk[1])?;
            key[index] = msd << 4 | lsd;
        }
        Ok(Self(key))
    }
}

impl TryFrom<&str> for Key {
    type Error = DecodeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let v = BASE64_STANDARD.decode(value)?;
        if v.len() == KEY_LENGTH {
            let buf = v.try_into().map_err(|_| Self::Error::InvalidLength)?;
            Ok(Self::new(buf))
        } else {
            Err(Self::Error::InvalidLength)
        }
    }
}

impl TryFrom<&String> for Key {
    type Error = DecodeError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        let v = BASE64_STANDARD.decode(value)?;
        if v.len() == KEY_LENGTH {
            let buf = v.try_into().map_err(|_| Self::Error::InvalidLength)?;
            Ok(Self::new(buf))
        } else {
            Err(Self::Error::InvalidLength)
        }
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == KEY_LENGTH {
            let buf =
                <[u8; KEY_LENGTH]>::try_from(value).map_err(|_| Self::Error::InvalidLength)?;
            Ok(Self::new(buf))
        } else {
            Err(Self::Error::InvalidLength)
        }
    }
}

impl FromStr for Key {
    type Err = DecodeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let v = BASE64_STANDARD.decode(value)?;
        if v.len() == KEY_LENGTH {
            let buf = v.try_into().map_err(|_| Self::Err::InvalidLength)?;
            Ok(Self::new(buf))
        } else {
            Err(Self::Err::InvalidLength)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_key() {
        let key_str = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::decode(key_str).unwrap();
        assert_eq!(
            key.0,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
                0x3c, 0x2d, 0x1e, 0x0f
            ]
        );
        assert_eq!(key.to_lower_hex(), key_str);
        assert_eq!(
            format!("{key}"),
            "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8="
        );
    }

    #[test]
    fn parse_key() {
        let key_str = "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=";
        let key: Key = key_str.try_into().unwrap();
        assert_eq!(
            key.0,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
                0x3c, 0x2d, 0x1e, 0x0f
            ]
        );
        assert_eq!(
            key.to_lower_hex(),
            "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f"
        );
        assert_eq!(format!("{key}"), key_str);
    }
}
