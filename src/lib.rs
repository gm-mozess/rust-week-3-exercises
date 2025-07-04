use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        // TODO: Construct a CompactSize from a u64 value
        Self { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Encode according to Bitcoin's CompactSize format:
        // [0x00–0xFC] => 1 byte
        // [0xFDxxxx] => 0xFD + u16 (2 bytes)
        // [0xFExxxxxxxx] => 0xFE + u32 (4 bytes)
        // [0xFFxxxxxxxxxxxxxxxx] => 0xFF + u64 (8 bytes)
        match self.value {
            0..=252 => vec![self.value as u8],
            253..=65535 => {
                let mut bytes = vec![0xFD];
                bytes.extend_from_slice(&(self.value as u16).to_le_bytes());
                bytes
            }
            65536..=4294967295 => {
                let mut bytes = vec![0xFE];
                bytes.extend_from_slice(&(self.value as u32).to_le_bytes());
                bytes
            }
            _ => {
                let mut bytes = vec![0xFF];
                bytes.extend_from_slice(&self.value.to_le_bytes());
                bytes
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Decode CompactSize, returning value and number of bytes consumed.
        // First check if bytes is empty.
        // Check that enough bytes are available based on prefix.
        if bytes.is_empty() {
            return Err(BitcoinError::InsufficientBytes);
        }

        let first_byte = bytes[0];

        match first_byte {
            0..=252 => {
                let value = first_byte as u64;
                Ok((CompactSize::new(value), 1))
            }
            253 => {
                if bytes.len() < 3 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u16::from_le_bytes([bytes[1], bytes[2]]) as u64;
                Ok((CompactSize::new(value), 3))
            }
            254 => {
                if bytes.len() < 5 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
                Ok((CompactSize::new(value), 5))
            }
            255 => {
                if bytes.len() < 9 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                Ok((CompactSize::new(value), 9))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = self
            .0
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for Txid {
    // TODO: Parse hex string into 32-byte array
    // Use `hex::decode`, validate length = 32
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_string = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;

        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Txid must be exactly 32 bytes"));
        }

        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&bytes);
        Ok(Txid(txid_bytes))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    // TODO: Create an OutPoint from raw txid bytes and output index
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self {
            txid: Txid(txid),
            vout,
        }
    }
    // TODO: Serialize as: txid (32 bytes) + vout (4 bytes, little-endian)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.txid.0);
        bytes.extend_from_slice(&self.vout.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Deserialize in order:
        // - OutPoint (36 bytes)
        // - Script (with CompactSize)
        // - Sequence (4 bytes)
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }

        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&bytes[0..32]);

        let vout = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);

        Ok((OutPoint::new(txid_bytes, vout), 36))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let length = CompactSize::new(self.bytes.len() as u64);
        let mut result = length.to_bytes();
        result.extend_from_slice(&self.bytes);
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Parse CompactSize prefix, then read that many bytes
        // Return error if not enough bytes
        let (length, length_bytes_consumed) = CompactSize::from_bytes(bytes)?;
        let script_len = length.value as usize;

        let total_needed = length_bytes_consumed + script_len;
        if bytes.len() < total_needed {
            return Err(BitcoinError::InsufficientBytes);
        }

        let script_bytes =
            bytes[length_bytes_consumed..length_bytes_consumed + script_len].to_vec();
        Ok((Script::new(script_bytes), total_needed))
    }
}

impl Deref for Script {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        Self {
            previous_output,
            script_sig,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Serialize: OutPoint + Script (with CompactSize) + sequence (4 bytes LE)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.previous_output.to_bytes());
        bytes.extend_from_slice(&self.script_sig.to_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Deserialize in order:
        // - OutPoint (36 bytes)
        // - Script (with CompactSize)
        // - Sequence (4 bytes)
        let mut offset = 0;

        // Parse OutPoint (36 bytes)
        let (previous_output, outpoint_consumed) = OutPoint::from_bytes(&bytes[offset..])?;
        offset += outpoint_consumed;

        // Parse Script (with CompactSize prefix)
        let (script_sig, script_consumed) = Script::from_bytes(&bytes[offset..])?;
        offset += script_consumed;

        // Parse sequence (4 bytes)
        if bytes.len() < offset + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let sequence = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        Ok((
            TransactionInput::new(previous_output, script_sig, sequence),
            offset,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        Self {
            version,
            inputs,
            lock_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Format:
        // - version (4 bytes LE)
        // - CompactSize (number of inputs)
        // - each input serialized
        // - lock_time (4 bytes LE)
        let mut bytes = Vec::new();

        // Version (4 bytes LE)
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // CompactSize for number of inputs
        let input_count = CompactSize::new(self.inputs.len() as u64);
        bytes.extend_from_slice(&input_count.to_bytes());

        // Each input serialized
        for input in &self.inputs {
            bytes.extend_from_slice(&input.to_bytes());
        }

        // Lock time (4 bytes LE)
        bytes.extend_from_slice(&self.lock_time.to_le_bytes());

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Read version, CompactSize for input count
        // Parse inputs one by one
        // Read final 4 bytes for lock_time
        let mut offset = 0;

        // Read version (4 bytes)
        if bytes.len() < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        offset += 4;

        // Read CompactSize for input count
        let (input_count, count_bytes_consumed) = CompactSize::from_bytes(&bytes[offset..])?;
        offset += count_bytes_consumed;

        // Parse inputs
        let mut inputs = Vec::new();
        for _ in 0..input_count.value {
            let (input, input_bytes_consumed) = TransactionInput::from_bytes(&bytes[offset..])?;
            inputs.push(input);
            offset += input_bytes_consumed;
        }

        // Read lock_time (4 bytes)
        if bytes.len() < offset + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let lock_time = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        Ok((BitcoinTransaction::new(version, inputs, lock_time), offset))
    }
}

impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Format a user-friendly string showing version, inputs, lock_time
        // Display scriptSig length and bytes, and previous output info
        writeln!(f, "Bitcoin Transaction:")?;
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Inputs: {}", self.inputs.len())?;

        for input in self.inputs.iter() {
            writeln!(f, "Previous Output Vout: {:?}", input.previous_output.vout)?;
        }

        writeln!(f, "Lock Time: {}", self.lock_time)?;

        Ok(())
    }
}
