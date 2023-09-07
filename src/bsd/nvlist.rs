// https://github.com/freebsd/freebsd-src/tree/main/sys/contrib/libnv
// https://github.com/freebsd/freebsd-src/blob/main/sys/sys/nv.h
use std::{error::Error, ffi::CStr, fmt};

/// `NV_HEADER_SIZE` is for both: `nvlist_header` and `nvpair_header`.
const NV_HEADER_SIZE: usize = 19;
const NV_NAME_MAX: usize = 2048;
const NVLIST_HEADER_MAGIC: u8 = 0x6c; // 'l'
const NVLIST_HEADER_VERSION: u8 = 0;
// Public flags
// Perform case-insensitive lookups of provided names.
// const NV_FLAG_IGNORE_CASE: u8 = 1;
// Names don't have to be unique.
// const NV_FLAG_NO_UNIQUE: u8 = 2;
// Private flags
const NV_FLAG_BIG_ENDIAN: u8 = 0x80;
// const NV_FLAG_IN_ARRAY: u8 = 0x100;

#[derive(Debug)]
#[repr(u8)]
pub enum NvType {
    None,
    Null,
    Bool,
    Number,
    String,
    NvList,
    _Descriptor,
    Binary,
    BoolArray,
    NumberArray,
    StringArray,
    NvListArray,
    _DescriptorArray,
    // must have a parent
    NvListArrayNext = 254,
    NvListAUp,
}

impl From<u8> for NvType {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::Null,
            2 => Self::Bool,
            3 => Self::Number,
            4 => Self::String,
            5 => Self::NvList,
            6 => Self::_Descriptor,
            7 => Self::Binary,
            8 => Self::BoolArray,
            9 => Self::NumberArray,
            10 => Self::StringArray,
            11 => Self::NvListArray,
            12 => Self::_DescriptorArray,
            254 => Self::NvListArrayNext,
            255 => Self::NvListAUp,
            _ => Self::None,
        }
    }
}

#[derive(Debug)]
pub enum NvValue<'a> {
    Null,
    Bool(bool),
    Number(u64),
    String(&'a str),
    NvList(NvList<'a>),
    _Descriptor, // not implemented
    Binary(&'a [u8]),
    Bytes(Vec<u8>), // similar to `Binary`, but owned
    BoolArray(Vec<bool>),
    NumberArray(Vec<u64>),
    StringArray(Vec<&'a str>),
    NvListArray(Vec<NvList<'a>>),
    _DescriptorArray, // not implemented
    NvListArrayNext,
    // NvListAUp,
}

impl<'a> NvValue<'a> {
    /// Return number of bytes this value occupies when packed.
    #[must_use]
    pub fn byte_size(&self) -> usize {
        match self {
            Self::Null | Self::_Descriptor | Self::_DescriptorArray | Self::NvListArrayNext => 0,
            Self::Bool(_) => 1,
            Self::Number(_) => 8,
            Self::String(string) => string.len() + 1, // +1 for NUL
            Self::NvList(list) => list.byte_size(),   // FIXME: not sure about this
            Self::Binary(binary) => binary.len(),
            Self::Bytes(bytes) => bytes.len(),
            Self::BoolArray(array) => array.len(),
            Self::NumberArray(array) => array.len() * 8,
            Self::StringArray(array) => array.iter().fold(0, |size, el| size + el.len() + 1),
            Self::NvListArray(array) => array.iter().fold(0, |size, el| size + el.byte_size()),
        }
    }

    #[must_use]
    pub fn nv_type(&self) -> NvType {
        match self {
            Self::Null => NvType::Null,
            Self::Bool(_) => NvType::Bool,
            Self::Number(_) => NvType::Number,
            Self::String(_) => NvType::String,
            Self::NvList(_) => NvType::NvList,
            Self::_Descriptor => NvType::_Descriptor,
            Self::Binary(_) | Self::Bytes(_) => NvType::Binary,
            Self::BoolArray(_) => NvType::BoolArray,
            Self::NumberArray(_) => NvType::NumberArray,
            Self::StringArray(_) => NvType::StringArray,
            Self::NvListArray(_) => NvType::NvListArray,
            Self::_DescriptorArray => NvType::_DescriptorArray,
            Self::NvListArrayNext => NvType::NvListArrayNext,
        }
    }

    #[must_use]
    pub fn number_of_items(&self) -> usize {
        match self {
            Self::BoolArray(v) => v.len(),
            Self::NumberArray(v) => v.len(),
            Self::StringArray(v) => v.len(),
            Self::NvListArray(v) => v.len(),
            _ => 0, // non-array
        }
    }
}

#[derive(Debug)]
pub enum NvListError {
    NameTooLong,
    NotEnoughBytes,
    WrongHeader,
    WrongName,
    WrongPair,
    WrongPairData,
}

impl Error for NvListError {}

impl fmt::Display for NvListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameTooLong => write!(f, "name is too long"),
            Self::NotEnoughBytes => write!(f, "not enough bytes"),
            Self::WrongHeader => write!(f, "wrong header"),
            Self::WrongName => write!(f, "wrong name"),
            Self::WrongPair => write!(f, "wrong name-value pair"),
            Self::WrongPairData => write!(f, "wrong name-value pair data"),
        }
    }
}

/// `NvList` is a name-value list.
/// It is meant to live shortly. Just build the list and serialize it to bytes.
type NameValue<'a> = (&'a str, NvValue<'a>);
#[derive(Debug)]
pub struct NvList<'a> {
    items: Vec<NameValue<'a>>,
    is_big_endian: bool,
}

impl<'a> Default for NvList<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> NvList<'a> {
    /// Create new `NvList`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            #[cfg(target_endian = "big")]
            is_big_endian: true,
            #[cfg(target_endian = "little")]
            is_big_endian: false,
        }
    }

    /// Get value for a given `name`.
    fn get(&self, name: &str) -> Option<&NvValue> {
        self.items.iter().find(|(n, _)| n == &name).map(|(_, v)| v)
    }

    /// Get value as `bool`.
    // pub fn get_bool(&self, name: &str) -> Option<bool> {
    //     self.get(name).and_then(|value| match value {
    //         NvValue::Bool(boolean) => Some(*boolean),
    //         _ => None,
    //     })
    // }

    /// Get value as `u64`.
    pub fn get_number(&self, name: &str) -> Option<u64> {
        self.get(name).and_then(|value| match value {
            NvValue::Number(number) => Some(*number),
            _ => None,
        })
    }

    /// Get value as `&str`.
    // pub fn get_string(&self, name: &str) -> Option<&str> {
    //     self.get(name).and_then(|value| match value {
    //         NvValue::String(string) => Some(*string),
    //         _ => None,
    //     })
    // }

    /// Get value as `&[u8]`.
    pub fn get_binary(&self, name: &str) -> Option<&[u8]> {
        self.get(name).and_then(|value| match value {
            NvValue::Binary(binary) => Some(*binary),
            _ => None,
        })
    }

    /// Get value as `Vec<NvList>`
    pub fn get_nvlist_array(&self, name: &str) -> Option<&[NvList]> {
        self.get(name).and_then(|value| match value {
            NvValue::NvListArray(array) => Some(array.as_slice()),
            _ => None,
        })
    }

    /// Append `Null` value to the list.
    #[cfg(test)]
    pub fn append_null(&mut self, name: &'a str) {
        self.items.push((name, NvValue::Null));
    }

    /// Append `Bool` value to the list.
    pub fn append_bool(&mut self, name: &'a str, boolean: bool) {
        self.items.push((name, NvValue::Bool(boolean)));
    }

    /// Append `Number` value to the list.
    pub fn append_number(&mut self, name: &'a str, number: u64) {
        self.items.push((name, NvValue::Number(number)));
    }

    /// Append `String` value to the list.
    // pub fn append_string(&mut self, name: &'a str, string: &'a str) {
    //     self.items.push((name, NvValue::String(string)));
    // }

    /// Append `Binary` value to the list.
    pub fn append_binary(&mut self, name: &'a str, binary: &'a [u8]) {
        self.items.push((name, NvValue::Binary(binary)));
    }

    /// Append `Bytes` value to the list.
    pub fn append_bytes(&mut self, name: &'a str, bytes: Vec<u8>) {
        self.items.push((name, NvValue::Bytes(bytes)));
    }

    /// Append `NvListArray` value to the list.
    pub fn append_nvlist_array(&mut self, name: &'a str, array: Vec<NvList<'a>>) {
        self.items.push((name, NvValue::NvListArray(array)));
    }

    /// Append `NvListArrayNext` value to the list.
    pub fn append_nvlist_array_next(&mut self) {
        self.items.push(("", NvValue::NvListArrayNext));
    }

    fn load_u16(&self, buf: &[u8]) -> Result<u16, NvListError> {
        if let Ok(bytes) = <[u8; 2]>::try_from(buf) {
            Ok(if self.is_big_endian {
                u16::from_be_bytes(bytes)
            } else {
                u16::from_le_bytes(bytes)
            })
        } else {
            Err(NvListError::NotEnoughBytes)
        }
    }

    fn load_u64(&self, buf: &[u8]) -> Result<u64, NvListError> {
        if let Ok(bytes) = <[u8; 8]>::try_from(buf) {
            Ok(if self.is_big_endian {
                u64::from_be_bytes(bytes)
            } else {
                u64::from_le_bytes(bytes)
            })
        } else {
            Err(NvListError::NotEnoughBytes)
        }
    }

    fn load_name(buf: &'a [u8]) -> Result<&'a str, NvListError> {
        CStr::from_bytes_with_nul(buf)
            .map_err(|_| NvListError::WrongName)?
            .to_str()
            .map_err(|_| NvListError::WrongName)
    }

    fn load_string(buf: &'a [u8]) -> Result<&'a str, NvListError> {
        CStr::from_bytes_until_nul(buf)
            .map_err(|_| NvListError::WrongPairData)?
            .to_str()
            .map_err(|_| NvListError::WrongPairData)
    }

    fn store_u16(&self, value: u16, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&if self.is_big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    }

    fn store_u64(&self, value: u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&if self.is_big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    }

    /// Return number of bytes this list occupies when packed.
    #[must_use]
    fn byte_size(&self) -> usize {
        let mut size = NV_HEADER_SIZE;
        for (name, value) in &self.items {
            size += NV_HEADER_SIZE + name.len() + 1; // +1 for NUL
            size += value.byte_size();
        }

        size
    }

    /// Pack name-value list to binary representation.
    pub fn pack(&self) -> Result<Vec<u8>, NvListError> {
        let size = self.byte_size();
        let mut buf = Vec::with_capacity(size);
        self.pack_with_size(&mut buf, size)?;
        Ok(buf)
    }

    /// Pack nvlist with pre-calculated buffer size.
    /// This is needed for list arrays where lists have fishy size.
    fn pack_with_size(
        &self,
        buf: &mut Vec<u8>,
        mut byte_size: usize,
    ) -> Result<usize, NvListError> {
        // pack header
        buf.push(NVLIST_HEADER_MAGIC);
        buf.push(NVLIST_HEADER_VERSION);
        buf.push(if self.is_big_endian {
            NV_FLAG_BIG_ENDIAN
        } else {
            0
        });
        self.store_u64(0, buf);
        byte_size -= NV_HEADER_SIZE;
        self.store_u64(byte_size as u64, buf);

        for (name, value) in &self.items {
            buf.push(value.nv_type() as u8);
            // name length
            let name_len = name.len() + 1;
            if name_len > NV_NAME_MAX {
                return Err(NvListError::NameTooLong);
            }
            self.store_u16(name_len as u16, buf);

            let value_size = match value {
                NvValue::NvListArray(_) => 0,
                _ => value.byte_size(),
            };
            self.store_u64(value_size as u64, buf);

            let number_of_items = value.number_of_items();
            self.store_u64(number_of_items as u64, buf);

            // name
            buf.extend_from_slice(name.as_bytes());
            buf.push(0); // NUL

            byte_size -= NV_HEADER_SIZE + name_len + value_size;

            match value {
                NvValue::Bool(boolean) => buf.push(u8::from(*boolean)),
                NvValue::Number(number) => self.store_u64(*number, buf),
                NvValue::String(string) => {
                    buf.extend_from_slice(string.as_bytes());
                    buf.push(0); // NUL
                }
                NvValue::Binary(bytes) => buf.extend_from_slice(bytes),
                NvValue::Bytes(bytes) => buf.extend_from_slice(bytes.as_slice()),
                NvValue::BoolArray(array) => {
                    array.iter().for_each(|boolean| buf.push((*boolean).into()));
                }
                NvValue::NumberArray(array) => {
                    array.iter().for_each(|number| self.store_u64(*number, buf));
                }
                NvValue::StringArray(array) => {
                    for string in array.iter() {
                        buf.extend_from_slice(string.as_bytes());
                        buf.push(0); // NUL
                    }
                }
                NvValue::NvListArray(nvlist_array) => {
                    for nvlist in nvlist_array {
                        byte_size = nvlist.pack_with_size(buf, byte_size)?;
                    }
                }
                NvValue::Null | NvValue::NvListArrayNext => (),
                _ => unimplemented!(),
            }
        }

        Ok(byte_size)
    }

    /// Unpack binary representation of name-value list.
    ///
    /// # Errors
    /// Return `Err` when buffer contains invalid data.
    pub fn unpack(&mut self, buf: &'a [u8]) -> Result<usize, NvListError> {
        let length = buf.len();
        // check header
        if length < NV_HEADER_SIZE {
            return Err(NvListError::NotEnoughBytes);
        }
        if buf[0] != NVLIST_HEADER_MAGIC || buf[1] != NVLIST_HEADER_VERSION {
            return Err(NvListError::WrongHeader);
        }
        self.is_big_endian = buf[2] & NV_FLAG_BIG_ENDIAN != 0;

        let _descriptors = self.load_u64(&buf[3..11])?;
        let size = self.load_u64(&buf[11..19])? as usize;

        // check total size
        if length < NV_HEADER_SIZE + size {
            return Err(NvListError::NotEnoughBytes);
        }

        let mut index = NV_HEADER_SIZE;
        while index < size {
            match self.nvpair_unpack(&buf[index..]) {
                Ok((count, last_element)) => {
                    index += count;
                    if last_element {
                        break;
                    }
                }
                Err(err) => return Err(err),
            }
        }

        Ok(index)
    }

    /// Unpack binary name-value pair and return number of consumed bytes and
    /// a flag indicating if array processing should be stopped (`true`), or not (`false`).
    ///
    /// # Errors
    /// Return `Err` when buffer contains invalid data.
    fn nvpair_unpack(&mut self, buf: &'a [u8]) -> Result<(usize, bool), NvListError> {
        let pair_type = NvType::from(buf[0]);
        let name_size = self.load_u16(&buf[1..3])? as usize;
        if name_size > NV_NAME_MAX {
            return Err(NvListError::WrongPair);
        }
        let size = self.load_u64(&buf[3..11])? as usize;
        // Used only for array types.
        let mut item_count = self.load_u64(&buf[11..NV_HEADER_SIZE])?;
        let mut index = NV_HEADER_SIZE + name_size;

        let name = Self::load_name(&buf[NV_HEADER_SIZE..index])?;
        let mut last_element = false;

        let value = match pair_type {
            NvType::Null => {
                if size != 0 {
                    return Err(NvListError::WrongPairData);
                }
                NvValue::Null
            }
            NvType::Bool => {
                if size != 1 {
                    return Err(NvListError::WrongPairData);
                }
                let boolean = buf[index] != 0;
                NvValue::Bool(boolean)
            }
            NvType::Number => {
                if size != 8 {
                    return Err(NvListError::WrongPairData);
                }
                let number = self.load_u64(&buf[index..index + size])?;
                NvValue::Number(number)
            }
            NvType::String => {
                if size == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let string = Self::load_string(&buf[index..index + size])?;
                // TODO: if string.len() + 1 != size {}
                NvValue::String(string)
            }
            NvType::NvList => {
                // TODO: read list elements
                NvValue::NvList(NvList::new())
            }
            NvType::Binary => {
                if size == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let binary = &buf[index..index + size];
                NvValue::Binary(binary)
            }
            NvType::BoolArray => {
                if size == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let array = buf[index..index + size]
                    .iter()
                    .map(|byte| *byte != 0)
                    .collect();
                NvValue::BoolArray(array)
            }
            NvType::NumberArray => {
                if size == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let mut array = Vec::with_capacity(item_count as usize);
                for chunk in buf[index..index + size].chunks(8) {
                    array.push(self.load_u64(chunk)?);
                }
                NvValue::NumberArray(array)
            }
            NvType::StringArray => {
                if size == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let mut array = Vec::with_capacity(item_count as usize);
                let mut i = index;
                let mut s = size;
                for _ in 0..item_count {
                    let string = Self::load_string(&buf[i..i + s])?;
                    array.push(string);
                    i += string.len() + 1;
                    s -= string.len() + 1;
                }
                NvValue::StringArray(array)
            }
            NvType::NvListArray => {
                if size != 0 || item_count == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let mut array = Vec::with_capacity(item_count as usize);
                while item_count != 0 {
                    let mut list = NvList::new();
                    index += list.unpack(&buf[index..])?;
                    array.push(list);
                    item_count -= 1;
                }
                NvValue::NvListArray(array)
            }
            // This is a nasty hack: this type means we've reach the last item in the array.
            // Stop processing the array regardless of `nvlh_size` in (nested) NvList header.
            NvType::NvListArrayNext => {
                if size != 0 || item_count != 0 {
                    return Err(NvListError::WrongPairData);
                }
                last_element = true;
                NvValue::NvListArrayNext
            }
            _ => unimplemented!(),
        };
        self.items.push((name, value));

        Ok((index + size, last_element))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rustfmt::skip]
    static TEST_DATA: [u8; 81] = [
        // *** nvlist_header (19 bytes)
        108, // nvlh_magic
        0,   // nvlh_version
        0,   // nvlh_flags
        0, 0, 0, 0, 0, 0, 0, 0, // nvlh_descriptors
        39 + 23, 0, 0, 0, 0, 0, 0, 0, // nvlh_size
        // *** data (nvlh_size bytes)
        // *** nvpair_header (19 bytes)
        3, // nvph_type = NV_TYPE_NUMBER
        12, 0, // nvph_namesize (incl. NUL)
        8, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
        0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
        108, 105, 115, 116, 101, 110, 45, 112, 111, 114, 116, 0, // "listen-port\0"
        57, 48, 0, 0, 0, 0, 0, 0, // 12345

        1, // nvph_type = NV_TYPE_NULL
        4, 0, // nvph_namesize (incl. NUL)
        0, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
        0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
        'n' as u8, 'u' as u8, 'l' as u8, 0,
    ];

    #[test]
    fn unpack() {
        let mut nvlist = NvList::new();
        nvlist.unpack(&TEST_DATA).unwrap();

        let buf = nvlist.pack().unwrap();

        let mut nvlist = NvList::new();
        nvlist.unpack(&buf).unwrap();

        assert_eq!(TEST_DATA.as_slice(), buf.as_slice());
    }

    #[test]
    fn pack() {
        let mut nvlist = NvList::new();
        nvlist.append_number("listen-port", 12345);
        nvlist.append_null("nul");

        let buf = nvlist.pack().unwrap();
        assert_eq!(TEST_DATA.as_slice(), buf.as_slice());
    }

    #[test]
    fn bool_array() {
        #[rustfmt::skip]
        let data = [
            108,0,0,
            0,0,0,0,0,0,0,0,
            27,0,0,0,0,0,0,0,
            8,4,0, // NV_TYPE_BOOL_ARRAY
            4,0,0,0,0,0,0,0, // size
            4,0,0,0,0,0,0,0, // items
            98,117,108,0, // "bul\0"
            1,0,0,1,
        ];
        let mut nvlist = NvList::new();
        nvlist.unpack(&data).unwrap();

        let buf = nvlist.pack().unwrap();
        assert_eq!(data.as_slice(), buf.as_slice());
    }

    #[test]
    fn number_array() {
        #[rustfmt::skip]
        let data = [
            108,0,0,
            0,0,0,0,0,0,0,0,
            40,0,0,0,0,0,0,0,
            9,5,0,
            16,0,0,0,0,0,0,0,
            2,0,0,0,0,0,0,0,
            110,117,109,115,0, // "nums\0"
            68,51,34,17,0,0,0,0, 136,119,102,85,0,0,0,0,
        ];
        let mut nvlist = NvList::new();
        nvlist.unpack(&data).unwrap();

        let buf = nvlist.pack().unwrap();
        assert_eq!(data.as_slice(), buf.as_slice());
    }

    #[test]
    fn string_array() {
        #[rustfmt::skip]
        let data = [
            108,0,0,
            0,0,0,0,0,0,0,0,
            42,0,0,0,0,0,0,0,
            10,6,0,
            17,0,0,0,0,0,0,0,
            3,0,0,0,0,0,0,0,
            110,97,109,101,115,0,
            83,116,117,97,114,116,0, 75,101,118,105,110,0, 66,111,98,0,
        ];
        let mut nvlist = NvList::new();
        nvlist.unpack(&data).unwrap();

        let buf = nvlist.pack().unwrap();
        assert_eq!(data.as_slice(), buf.as_slice());
    }

    #[test]
    fn two_peers() {
        #[rustfmt::skip]
        let data = [
            // nvlist
            108, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            121, 3, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 12, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            108, 105, 115, 116, 101, 110, 45, 112, 111, 114, 116, 0, // "listen-port\0"
            133, 28, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 11, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, // "public-key\0"
            77, 206, 217, 13, 140, 115, 50, 63, 20, 85, 182, 151, 82, 219, 246, 40, 224, 195, 180, 210, 240, 16, 47, 189, 89, 167, 240, 131, 81, 17, 68, 111,
            // NV_TYPE_NUMBER
            7, 12, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 105, 118, 97, 116, 101, 45, 107, 101, 121, 0, // "private-key\0"
            184, 70, 130, 139, 240, 172, 115, 210, 42, 253, 145, 16, 84, 163, 217, 206, 219, 207, 194, 29, 250, 97, 48, 232, 184, 78, 19, 62, 194, 45, 133, 77,
            // NV_TYPE_NVLIST_ARRAY
            11, 6, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            2, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 101, 114, 115, 0, // "peers\0"
            // nvlist
            108, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            169, 2, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 11, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, // "public-key\0"
            220, 98, 132, 114, 211, 195, 157, 56, 63, 135, 95, 253, 123, 132, 59, 218, 35, 120, 55, 169, 156, 165, 223, 184, 140, 111, 142, 164, 145, 107, 167, 17,
            // NV_TYPE_BINARY
            7, 14, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 101, 115, 104, 97, 114, 101, 100, 45, 107, 101, 121, 0, // "preshared-key\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 20, 0,
            16, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            108, 97, 115, 116, 45, 104, 97, 110, 100, 115, 104, 97, 107, 101, 45, 116, 105, 109, 101, 0, // "last-handshake-time\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 30, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 114, 115, 105, 115, 116, 101, 110, 116, 45, 107, 101, 101, 112, 97, 108, 105, 118, 101, 45, 105, 110, 116, 101, 114, 118, 97, 108, 0, // "persistent-keepalive-interval\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            114, 120, 45, 98, 121, 116, 101, 115, 0, // "rx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            116, 120, 45, 98, 121, 116, 101, 115, 0, // "tx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NVLIST_ARRAY_NEXT
            254, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0,
            // nvlist
            108, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            75, 1, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 11, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, // "public-key\0"
            60, 195, 52, 243, 24, 229, 218, 5, 142, 193, 30, 194, 241, 176, 169, 221, 121, 39, 172, 116, 158, 67, 46, 115, 119, 155, 107, 159, 128, 201, 79, 54,
            // NV_TYPE_BINARY
            7, 14, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 101, 115, 104, 97, 114, 101, 100, 45, 107, 101, 121, 0, // "preshared-key\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 20, 0,
            16, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            108, 97, 115, 116, 45, 104, 97, 110, 100, 115, 104, 97, 107, 101, 45, 116, 105, 109, 101, 0, // "last-handshake-time\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 30, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 114, 115, 105, 115, 116, 101, 110, 116, 45, 107, 101, 101, 112, 97, 108, 105, 118, 101, 45, 105, 110, 116, 101, 114, 118, 97, 108, 0, // "persistent-keepalive-interval\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            114, 120, 45, 98, 121, 116, 101, 115, 0, // "rx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            116, 120, 45, 98, 121, 116, 101, 115, 0, // "tx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NVLIST_ARRAY_NEXT
            254, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0];
        let mut nvlist = NvList::new();
        nvlist.unpack(&data).unwrap();

        let buf = nvlist.pack().unwrap();
        assert_eq!(data.as_slice(), buf.as_slice());

        let mut nvlist = NvList::new();
        nvlist.unpack(&buf).unwrap();
    }
}
