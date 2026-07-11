// SPDX-License-Identifier: Apache-2.0

//! Avatar image handling.
//!
//! Avatars are stored in the config as a canonical [`AVATAR_SIZE`]×[`AVATAR_SIZE`]
//! PNG. When connecting, a small [`DISPLAY_SIZE`]×[`DISPLAY_SIZE`] thumbnail is
//! derived and shared with the server so peers can render it beside the user's
//! name. This module centralises the decode/resize/encode logic and the base64
//! (de)serialisation used to embed avatar bytes in the TOML/JSON config.

use std::io::Cursor;

use anyhow::{Context, Result};
use image::{DynamicImage, ImageFormat, ImageReader, imageops::FilterType};

/// Edge length, in pixels, of the canonical avatar stored in the config.
pub const AVATAR_SIZE: u32 = 512;

/// Edge length, in pixels, used when displaying avatars in lists and chat.
pub const DISPLAY_SIZE: u32 = 32;

/// Normalise raw RGBA pixels (for example from the clipboard) into a square
/// [`AVATAR_SIZE`]×[`AVATAR_SIZE`] PNG suitable for storing in the config.
///
/// # Errors
///
/// Returns an error if the pixel buffer does not match `width`×`height`×4, or if
/// PNG encoding fails.
pub fn normalize_rgba(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>> {
    let buffer = image::RgbaImage::from_raw(width, height, rgba.to_vec())
        .context("clipboard image dimensions do not match its pixel data")?;
    encode_png(&resize_square(
        &DynamicImage::ImageRgba8(buffer),
        AVATAR_SIZE,
    ))
}

/// Normalise an encoded image file (PNG, JPEG, …) into a canonical avatar PNG.
///
/// # Errors
///
/// Returns an error if the format cannot be guessed, the image cannot be
/// decoded, or PNG encoding fails.
pub fn normalize_encoded(data: &[u8]) -> Result<Vec<u8>> {
    let image = ImageReader::new(Cursor::new(data))
        .with_guessed_format()?
        .decode()?;
    encode_png(&resize_square(&image, AVATAR_SIZE))
}

/// Produce a [`DISPLAY_SIZE`]×[`DISPLAY_SIZE`] PNG thumbnail from a stored avatar
/// PNG, for sharing with the server and rendering by peers.
///
/// # Errors
///
/// Returns an error if the stored avatar cannot be decoded or the thumbnail
/// cannot be encoded.
pub fn thumbnail(avatar_png: &[u8]) -> Result<Vec<u8>> {
    let image = image::load_from_memory(avatar_png)?;
    encode_png(&resize_square(&image, DISPLAY_SIZE))
}

/// Decode a PNG into raw RGBA pixels plus its (square) edge length, ready to be
/// wrapped in an `egui::ColorImage` texture.
///
/// # Errors
///
/// Returns an error if the bytes cannot be decoded as an image.
pub fn decode_rgba(png: &[u8]) -> Result<(Vec<u8>, usize)> {
    let image = image::load_from_memory(png)?.into_rgba8();
    let edge = image.width() as usize;
    Ok((image.into_raw(), edge))
}

/// Resize an image to a centred, cropped `size`×`size` square.
fn resize_square(image: &DynamicImage, size: u32) -> DynamicImage {
    image.resize_to_fill(size, size, FilterType::Lanczos3)
}

/// Encode an image as PNG bytes.
fn encode_png(image: &DynamicImage) -> Result<Vec<u8>> {
    let mut out = Cursor::new(Vec::new());
    image.write_to(&mut out, ImageFormat::Png)?;
    Ok(out.into_inner())
}

/// serde helpers for `Option<Vec<u8>>` avatar bytes, encoded as base64 so they
/// embed cleanly in TOML/JSON config files.
pub mod serde_b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize optional avatar bytes as an optional base64 string.
    ///
    /// # Errors
    ///
    /// Propagates serializer errors.
    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize optional avatar bytes from an optional base64 string.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string cannot be decoded.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        match Option::<String>::deserialize(deserializer)? {
            Some(text) => STANDARD.decode(text).map(Some).map_err(Error::custom),
            None => Ok(None),
        }
    }
}
