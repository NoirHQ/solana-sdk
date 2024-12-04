// Copyright (c) Haderech Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use bincode::{
    self as v2,
    error::{DecodeError, EncodeError},
};
use {
    alloc::{boxed::Box, vec::Vec},
    bincode::config,
    serde::Serialize,
};

/// Serializes an object directly into a `Writer` using the default configuration.
///
/// If the serialization would take more bytes than allowed by the size limit, an error
/// is returned and *no bytes* will be written into the `Writer`.
//pub fn serialize_into<W, T: ?Sized>(writer: W, value: &T) -> Result<(), Error>
//where
//    W: std::io::Write,
//    T: serde::Serialize,
//{
pub fn serialize_into<T>(writer: &mut [u8], value: &T) -> Result<(), Error>
where
    T: ?Sized + serde::Serialize,
{
    let writer = bincode::enc::write::SliceWriter::new(writer);
    Ok(bincode::serde::encode_into_writer(
        value,
        writer,
        config::legacy(),
    )?)
}

/// Serializes a serializable object into a `Vec` of bytes using the default configuration.
pub fn serialize<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: ?Sized + Serialize,
{
    Ok(bincode::serde::encode_to_vec(value, config::legacy())?)
}

/// Deserializes a slice of bytes into an instance of `T` using the default configuration.
pub fn deserialize<'a, T>(bytes: &'a [u8]) -> Result<T, Error>
where
    T: serde::de::Deserialize<'a>,
{
    Ok(bincode::serde::decode_borrowed_from_slice(
        bytes,
        config::legacy(),
    )?)
}

/// Returns the size that an object would be if serialized using Bincode with the default
/// configuration.
pub fn serialized_size<T>(value: &T) -> Result<u64, Error>
where
    T: ?Sized + serde::Serialize,
{
    let mut writer = bincode::enc::write::SizeWriter::default();
    bincode::serde::encode_into_writer(value, &mut writer, config::legacy())?;
    Ok(writer.bytes_written as u64)
}

pub type Error = Box<ErrorKind>;

#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error("the size limit has been reached")]
    SizeLimit,
    #[error("{0}")]
    Decode(DecodeError),
    #[error("{0}")]
    Encode(EncodeError),

    // for tests
    #[cfg(feature = "std")]
    #[error("{0}")]
    Custom(String),
    #[cfg(feature = "std")]
    #[error("{0}")]
    Io(std::io::Error),
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        match e {
            #[cfg(feature = "std")]
            DecodeError::OtherString(msg) => Box::new(ErrorKind::Custom(msg)),
            #[cfg(feature = "std")]
            DecodeError::UnexpectedEnd { .. } => {
                Box::new(ErrorKind::Io(std::io::ErrorKind::UnexpectedEof.into()))
            }
            _ => Box::new(ErrorKind::Decode(e)),
        }
    }
}

impl From<EncodeError> for Error {
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::UnexpectedEnd => Box::new(ErrorKind::SizeLimit),
            _ => Box::new(ErrorKind::Encode(e)),
        }
    }
}
