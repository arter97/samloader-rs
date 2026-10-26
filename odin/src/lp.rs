// Copyright 2026 John "topjohnwu" Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Helper functions for inspecting Android Logical Partition (`liblp`) metadata
//! and sparse image containers to derive dynamic partition sizing.

use crate::firmware::FirmwareInfo;
use futures::StreamExt;
use futures::io::{AsyncRead, AsyncSeek};

const SPARSE_HEADER_MAGIC: u32 = 0xed26_ff3a;
const CHUNK_RAW: u16 = 0xcac1;
const CHUNK_FILL: u16 = 0xcac2;

const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616c_4467; // "gDal"
const LP_METADATA_HEADER_MAGIC: u32 = 0x414c_5030; // "0PLA"
const LP_TARGET_TYPE_LINEAR: u32 = 0;

const LP_GEOMETRY_OFFSET: usize = 0x1000;
const LP_PRIMARY_HEADER_OFFSET: usize = 0x3000;
const REQUIRED_LOGICAL_SIZE: usize = 256 * 1024;
const DECOMPRESS_PREFIX_LIMIT: usize = 512 * 1024;

/// Inspects a [`FirmwareInfo`] representing a `SUPER` partition and attempts to
/// parse the active linear extent sizes to determine the `super_used_size` in sectors.
pub(crate) async fn inspect_super_firmware_info<R: AsyncRead + AsyncSeek + Unpin>(
    info: &mut FirmwareInfo<'_, R>,
) -> Option<u32> {
    match info {
        FirmwareInfo::Normal(f) => {
            let prefix = std::pin::pin!(f.slices(DECOMPRESS_PREFIX_LIMIT))
                .next()
                .await?
                .ok()?;
            inspect_super_bytes(&prefix)
        }
        FirmwareInfo::Lz4(f) => {
            let decompressed = std::pin::pin!(f.decompressed_slices(DECOMPRESS_PREFIX_LIMIT))
                .next()
                .await?
                .ok()?;
            inspect_super_bytes(&decompressed)
        }
    }
}

/// Inspects raw or sparse bytes of a `super.img` payload and extracts the highest
/// allocated sector defined across all linear dynamic partition extents.
pub(crate) fn inspect_super_bytes(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    if magic == SPARSE_HEADER_MAGIC {
        let logical_data = unsparse_prefix(data, REQUIRED_LOGICAL_SIZE)?;
        parse_lp_metadata(&logical_data)
    } else {
        parse_lp_metadata(data)
    }
}

/// Unsparses only the prefix of a sparse image up to `target_size` bytes.
fn unsparse_prefix(data: &[u8], target_size: usize) -> Option<Vec<u8>> {
    if data.len() < 28 {
        return None;
    }

    let file_hdr_sz = u16::from_le_bytes(data[8..10].try_into().ok()?) as usize;
    let chunk_hdr_sz = u16::from_le_bytes(data[10..12].try_into().ok()?) as usize;
    let blk_sz = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;

    if blk_sz == 0 || chunk_hdr_sz < 12 || file_hdr_sz < 28 || data.len() < file_hdr_sz {
        return None;
    }

    let mut logical_buf = vec![0u8; target_size];
    let mut logical_pos = 0;
    let mut offset = file_hdr_sz;

    while offset + chunk_hdr_sz <= data.len() && logical_pos < target_size {
        let chunk_type = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
        let chunk_sz_blocks =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().ok()?) as usize;
        let total_sz = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().ok()?) as usize;

        if total_sz < chunk_hdr_sz {
            return None;
        }

        let chunk_bytes = chunk_sz_blocks.checked_mul(blk_sz)?;
        let data_offset = offset + chunk_hdr_sz;

        if chunk_type == CHUNK_RAW {
            let data_sz = total_sz - chunk_hdr_sz;
            let avail = data.len().saturating_sub(data_offset).min(data_sz);
            let to_copy = avail.min(target_size - logical_pos);
            logical_buf[logical_pos..logical_pos + to_copy]
                .copy_from_slice(&data[data_offset..data_offset + to_copy]);
        } else if chunk_type == CHUNK_FILL && data_offset + 4 <= data.len() {
            let fill_val = &data[data_offset..data_offset + 4];
            let to_fill = chunk_bytes.min(target_size - logical_pos);
            for i in 0..to_fill {
                logical_buf[logical_pos + i] = fill_val[i % 4];
            }
        }
        // CHUNK_DONT_CARE leaves zeroes intact

        logical_pos = logical_pos.saturating_add(chunk_bytes);
        offset = offset.checked_add(total_sz)?;
    }

    Some(logical_buf)
}

/// Parses the primary `liblp` metadata tables and computes the maximum extent end sector.
fn parse_lp_metadata(raw: &[u8]) -> Option<u32> {
    if raw.len() < LP_PRIMARY_HEADER_OFFSET + 104 {
        return None;
    }

    // Verify geometry header magic
    let geom_magic = u32::from_le_bytes(
        raw[LP_GEOMETRY_OFFSET..LP_GEOMETRY_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    if geom_magic != LP_METADATA_GEOMETRY_MAGIC {
        return None;
    }

    // Verify primary metadata header magic
    let hdr_magic = u32::from_le_bytes(
        raw[LP_PRIMARY_HEADER_OFFSET..LP_PRIMARY_HEADER_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    if hdr_magic != LP_METADATA_HEADER_MAGIC {
        return None;
    }

    let hdr_size = u32::from_le_bytes(
        raw[LP_PRIMARY_HEADER_OFFSET + 8..LP_PRIMARY_HEADER_OFFSET + 12]
            .try_into()
            .ok()?,
    ) as usize;

    let tables_start = LP_PRIMARY_HEADER_OFFSET.checked_add(hdr_size)?;

    // Extents table descriptor is at offset 92 from the start of the header
    let ext_desc_offset = LP_PRIMARY_HEADER_OFFSET + 92;
    let ext_offset =
        u32::from_le_bytes(raw[ext_desc_offset..ext_desc_offset + 4].try_into().ok()?) as usize;
    let ext_num = u32::from_le_bytes(
        raw[ext_desc_offset + 4..ext_desc_offset + 8]
            .try_into()
            .ok()?,
    ) as usize;
    let ext_entry_size = u32::from_le_bytes(
        raw[ext_desc_offset + 8..ext_desc_offset + 12]
            .try_into()
            .ok()?,
    ) as usize;

    if ext_entry_size < 24 {
        return None;
    }

    let mut max_sector: u64 = 0;
    let extents_base = tables_start.checked_add(ext_offset)?;

    for e in 0..ext_num {
        let pos = extents_base.checked_add(e.checked_mul(ext_entry_size)?)?;
        if pos + 20 > raw.len() {
            break;
        }

        let num_sectors = u64::from_le_bytes(raw[pos..pos + 8].try_into().ok()?);
        let target_type = u32::from_le_bytes(raw[pos + 8..pos + 12].try_into().ok()?);
        let target_data = u64::from_le_bytes(raw[pos + 12..pos + 20].try_into().ok()?);

        if target_type == LP_TARGET_TYPE_LINEAR {
            let end_sector = target_data.checked_add(num_sectors)?;
            if end_sector > max_sector {
                max_sector = end_sector;
            }
        }
    }

    if max_sector > 0 {
        u32::try_from(max_sector).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_raw_image(extents: &[(u64, u32, u64)]) -> Vec<u8> {
        let mut raw = vec![0u8; 128 * 1024];

        // Geometry at 0x1000
        raw[0x1000..0x1004].copy_from_slice(&LP_METADATA_GEOMETRY_MAGIC.to_le_bytes());

        // Header at 0x3000
        raw[0x3000..0x3004].copy_from_slice(&LP_METADATA_HEADER_MAGIC.to_le_bytes());
        let hdr_size: u32 = 256;
        raw[0x3008..0x300c].copy_from_slice(&hdr_size.to_le_bytes());

        // Extents descriptor at 0x3000 + 92
        let ext_desc_offset = 0x3000 + 92;
        let ext_offset: u32 = 0;
        let ext_num = extents.len() as u32;
        let ext_entry_size: u32 = 24;
        raw[ext_desc_offset..ext_desc_offset + 4].copy_from_slice(&ext_offset.to_le_bytes());
        raw[ext_desc_offset + 4..ext_desc_offset + 8].copy_from_slice(&ext_num.to_le_bytes());
        raw[ext_desc_offset + 8..ext_desc_offset + 12]
            .copy_from_slice(&ext_entry_size.to_le_bytes());

        let tables_start = 0x3000 + hdr_size as usize;
        for (i, &(num_sectors, target_type, target_data)) in extents.iter().enumerate() {
            let pos = tables_start + i * 24;
            raw[pos..pos + 8].copy_from_slice(&num_sectors.to_le_bytes());
            raw[pos + 8..pos + 12].copy_from_slice(&target_type.to_le_bytes());
            raw[pos + 12..pos + 20].copy_from_slice(&target_data.to_le_bytes());
        }

        raw
    }

    fn build_test_sparse_image(raw_payload: &[u8]) -> Vec<u8> {
        let blk_sz = 4096u32;
        let num_blks = (raw_payload.len() as u32) / blk_sz;
        let mut sparse = Vec::new();

        // Sparse header (28 bytes)
        sparse.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes()); // magic
        sparse.extend_from_slice(&1u16.to_le_bytes()); // major
        sparse.extend_from_slice(&0u16.to_le_bytes()); // minor
        sparse.extend_from_slice(&28u16.to_le_bytes()); // file_hdr_sz
        sparse.extend_from_slice(&12u16.to_le_bytes()); // chunk_hdr_sz
        sparse.extend_from_slice(&blk_sz.to_le_bytes()); // blk_sz
        sparse.extend_from_slice(&num_blks.to_le_bytes()); // total_blks
        sparse.extend_from_slice(&1u32.to_le_bytes()); // total_chunks
        sparse.extend_from_slice(&0u32.to_le_bytes()); // image_checksum

        // Chunk header (12 bytes)
        sparse.extend_from_slice(&CHUNK_RAW.to_le_bytes());
        sparse.extend_from_slice(&0u16.to_le_bytes());
        sparse.extend_from_slice(&num_blks.to_le_bytes());
        let total_sz = 12 + raw_payload.len() as u32;
        sparse.extend_from_slice(&total_sz.to_le_bytes());

        sparse.extend_from_slice(raw_payload);
        sparse
    }

    #[test]
    fn test_inspect_super_used_size() {
        let raw = build_test_raw_image(&[
            (1000, LP_TARGET_TYPE_LINEAR, 2048),
            (5000, LP_TARGET_TYPE_LINEAR, 10000), // end = 15000
            (2000, 1, 20000),                     // ZERO extent (target_type != 0), ignored
        ]);

        // Raw unsparse format
        assert_eq!(inspect_super_bytes(&raw), Some(15000));

        // Android sparse format
        let sparse = build_test_sparse_image(&raw);
        assert_eq!(inspect_super_bytes(&sparse), Some(15000));
    }
}
