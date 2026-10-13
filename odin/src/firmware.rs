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

use crate::progress::FlashEvent;
use fast_md5::Md5;
use futures::StreamExt;
use futures::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use futures::stream::{self, Stream};
use samloader_pit::PitEntry;
use std::borrow::Cow;
use std::io::{self, SeekFrom};

// This is asserted by Lz4FrameHeader so the header size is always 15
const LZ4_HEADER_SIZE: usize = 15;

/// Verifies the trailing MD5 checksum appended to `.tar.md5` package files.
pub async fn verify_md5_footer<R: AsyncRead + AsyncSeek + Unpin>(
    mut reader: R,
    name: &str,
) -> io::Result<()> {
    let file_size = reader.seek(SeekFrom::End(0)).await?;

    if file_size < 34 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File is too small to contain a valid MD5 footer",
        ));
    }

    // Read the last 512 bytes of the file. Since the TAR file must end with at least
    // two blocks of zeroes, the last null byte (0x00) marks the exact boundary
    // between the TAR payload and the appended plain-text MD5 footer.
    let seek_pos = file_size.saturating_sub(512);
    reader.seek(SeekFrom::Start(seek_pos)).await?;
    let mut last_bytes = vec![0u8; (file_size - seek_pos) as usize];
    reader.read_exact(&mut last_bytes).await?;

    // Find the last null byte (0x00)
    let mut last_null_idx = None;
    for i in (0..last_bytes.len()).rev() {
        if last_bytes[i] == 0 {
            last_null_idx = Some(i);
            break;
        }
    }

    let Some(null_idx) = last_null_idx else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid null separator for the MD5 footer",
        ));
    };

    let footer_start = null_idx + 1;
    let footer_bytes = &last_bytes[footer_start..];
    let footer_str = String::from_utf8_lossy(footer_bytes);
    let footer_line = footer_str.lines().last().unwrap_or_default();

    if footer_line.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid MD5 checksum at the end of the file",
        ));
    }

    let expected_hex = &footer_line[..32];
    let mut expected_bytes = [0u8; 16];
    for i in 0..16 {
        let hex_byte = &expected_hex[i * 2..i * 2 + 2];
        expected_bytes[i] = u8::from_str_radix(hex_byte, 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }

    // The payload size is the exact position up to the MD5 footer text
    let payload_size = file_size - footer_line.len() as u64 - 1;

    crate::progress::on_event(FlashEvent::Md5Start {
        name,
        size: payload_size,
    });

    let res: io::Result<()> = async {
        // Reset file pointer and compute MD5 over the payload only
        reader.seek(SeekFrom::Start(0)).await?;
        let mut hasher = Md5::new();
        let mut buffer = [0u8; 128 * 1024];
        let mut remaining = payload_size;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..to_read]).await?;
            hasher.update(&buffer[..to_read]);
            crate::progress::inc(to_read as u64);
            remaining -= to_read as u64;
        }

        let calculated_digest = hasher.finalize();
        if calculated_digest != expected_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MD5 verification failed! File is corrupted or modified.",
            ));
        }

        Ok(())
    }
    .await;

    if res.is_err() {
        crate::progress::on_event(FlashEvent::Md5Fail(name));
    } else {
        crate::progress::on_event(FlashEvent::Md5End(name));
    }

    res
}

/// Header containing metadata parsed from an LZ4 frame.
pub(crate) struct Lz4FrameHeader {
    /// Total size of the decompressed content in bytes.
    pub(crate) content_size: u64,
    /// Maximum size of a block in bytes.
    pub(crate) block_max_size: u64,
}

impl Lz4FrameHeader {
    /// Parses the LZ4 frame header from an async reader.
    pub(crate) async fn parse<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<Self> {
        let mut header = [0u8; LZ4_HEADER_SIZE];
        reader.read_exact(&mut header).await?;
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());

        if magic != 0x184D2204 {
            // We only support the standard LZ4 frame magic in this context,
            // not the skippable frames (0x184D2A50 - 0x184D2A5F)
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Not a valid LZ4 frame. Magic: 0x{:08X}", magic),
            ));
        }

        let flg = header[4];

        let version = (flg >> 6) & 0x03;
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported LZ4 version: {}", version),
            ));
        }

        let block_independence = ((flg >> 5) & 0x01) == 1;
        let block_checksum = ((flg >> 4) & 0x01) == 1;
        let content_size_flag = ((flg >> 3) & 0x01) == 1;
        let dict_id_flag = (flg & 0x01) == 1;

        if !content_size_flag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 content size must be enabled",
            ));
        }
        if block_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 block checksum must be disabled",
            ));
        }
        if !block_independence {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 block independence must be enabled",
            ));
        }
        if dict_id_flag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 dictionary ID must be disabled",
            ));
        }

        let bd = header[5];

        let block_max_size_code = (bd >> 4) & 0x07;
        let block_max_size = match block_max_size_code {
            4 => 64 * 1024,
            5 => 256 * 1024,
            6 => 1024 * 1024,
            7 => 4 * 1024 * 1024,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid block max size code: {}", block_max_size_code),
                ));
            }
        };

        let content_size = u64::from_le_bytes(header[6..14].try_into().unwrap());

        Ok(Self {
            content_size,
            block_max_size,
        })
    }
}

/// An uncompressed firmware file payload.
pub(crate) struct FirmwareFile<'a, R> {
    /// PIT partition entry associated with this file.
    pub(crate) pit_entry: &'a PitEntry,
    /// Asynchronous reader for the file content payload.
    pub(crate) file: R,
    /// Total size of the file in bytes.
    pub(crate) size: u64,
}

impl<'a, R: AsyncRead + AsyncSeek + Unpin> FirmwareFile<'a, R> {
    pub(crate) fn slices(
        &mut self,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<Vec<u8>>> + '_ {
        stream::unfold(
            (&mut self.file, self.size, false),
            move |(reader, mut remaining, mut started)| async move {
                if remaining == 0 {
                    return None;
                }
                if !started {
                    if let Err(e) = reader.seek(SeekFrom::Start(0)).await {
                        return Some((Err(e), (reader, 0, true)));
                    }
                    started = true;
                }
                let to_read = remaining.min(slice_max_bytes as u64) as usize;
                let mut buffer = vec![0u8; to_read];
                if let Err(e) = reader.read_exact(&mut buffer).await {
                    return Some((Err(e), (reader, 0, started)));
                }
                remaining -= to_read as u64;
                Some((Ok(buffer), (reader, remaining, started)))
            },
        )
    }
}

/// An LZ4-compressed firmware file payload.
pub(crate) struct FirmwareLz4File<'a, R> {
    /// PIT partition entry associated with this file.
    pub(crate) pit_entry: &'a PitEntry,
    /// Asynchronous reader for the file content payload.
    pub(crate) file: R,
    /// Total size of the compressed file in bytes.
    pub(crate) size: u64,
    /// Metadata header of the LZ4 frame.
    pub(crate) header: Lz4FrameHeader,
}

impl<'a, R: AsyncRead + AsyncSeek + Unpin> FirmwareLz4File<'a, R> {
    pub(crate) fn slices(
        &mut self,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<(usize, Vec<u8>)>> + '_ {
        let iter = Lz4SliceIterator {
            reader: &mut self.file,
            max_blocks: slice_max_bytes / (1024 * 1024),
            remaining_decompressed: self.header.content_size,
            started: false,
            finished: false,
        };
        stream::unfold(iter, |mut it| async move {
            it.next_slice().await.map(|item| (item, it))
        })
    }

    pub(crate) fn decompressed_slices(
        &mut self,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<Vec<u8>>> + '_ {
        let iter = Lz4DecompressedSliceIterator {
            reader: &mut self.file,
            block_max_size: self.header.block_max_size as usize,
            slice_max_bytes,
            leftover: Vec::new(),
            started: false,
            finished: false,
        };
        stream::unfold(iter, |mut it| async move {
            it.next_slice().await.map(|item| (item, it))
        })
    }
}

/// Enum wrapping a firmware file payload variant.
pub(crate) enum FirmwareInfo<'a, R> {
    /// Uncompressed normal firmware file payload.
    Normal(FirmwareFile<'a, R>),
    /// LZ4-compressed firmware file payload.
    Lz4(FirmwareLz4File<'a, R>),
}

impl<'a, R> FirmwareInfo<'a, R> {
    /// Returns the PIT partition entry associated with this payload.
    pub(crate) fn pit_entry(&self) -> &'a PitEntry {
        match self {
            FirmwareInfo::Normal(f) => f.pit_entry,
            FirmwareInfo::Lz4(f) => f.pit_entry,
        }
    }
}

impl<'a, R: AsyncRead + AsyncSeek + Unpin> FirmwareInfo<'a, R> {
    /// Reads the entire payload content, decompressing it if needed.
    pub(crate) async fn read_all(&mut self) -> io::Result<Vec<u8>> {
        match self {
            FirmwareInfo::Normal(f) => {
                f.file.seek(SeekFrom::Start(0)).await?;
                let mut data = vec![0u8; f.size as usize];
                f.file.read_exact(&mut data).await?;
                Ok(data)
            }
            FirmwareInfo::Lz4(f) => {
                let mut data = Vec::new();
                let content_size = f.header.content_size;
                let slice_size = (f.header.block_max_size as usize).max(64 * 1024);
                let mut slices = std::pin::pin!(f.decompressed_slices(slice_size));
                while let Some(slice) = slices.next().await {
                    data.extend_from_slice(&slice?);
                }
                if data.len() as u64 != content_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "LZ4 content size mismatch: expected {}, got {}",
                            content_size,
                            data.len()
                        ),
                    ));
                }
                Ok(data)
            }
        }
    }
}

struct Lz4SliceIterator<'r, R> {
    reader: &'r mut R,
    max_blocks: usize,
    remaining_decompressed: u64,
    started: bool,
    finished: bool,
}

impl<'r, R: AsyncRead + AsyncSeek + Unpin> Lz4SliceIterator<'r, R> {
    async fn next_slice(&mut self) -> Option<io::Result<(usize, Vec<u8>)>> {
        match self.try_next_slice().await {
            Ok(Some(slice)) => Some(Ok(slice)),
            Ok(None) => None,
            Err(e) => {
                self.finished = true;
                Some(Err(e))
            }
        }
    }

    async fn try_next_slice(&mut self) -> io::Result<Option<(usize, Vec<u8>)>> {
        if self.finished {
            return Ok(None);
        }
        if !self.started {
            self.reader
                .seek(SeekFrom::Start(LZ4_HEADER_SIZE as u64))
                .await?;
            self.started = true;
        }

        let mut buffer = Vec::new();
        let mut num_blocks = 0;

        while num_blocks < self.max_blocks {
            let mut size_bytes = [0u8; 4];
            self.reader.read_exact(&mut size_bytes).await?;

            let block_size = u32::from_le_bytes(size_bytes);
            if block_size == 0 {
                self.finished = true;
                break;
            }

            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            let start = buffer.len();
            buffer.resize(start + 4 + data_size, 0);
            buffer[start..start + 4].copy_from_slice(&size_bytes);
            self.reader.read_exact(&mut buffer[start + 4..]).await?;

            num_blocks += 1;
        }

        if buffer.is_empty() {
            return Ok(None);
        }

        let decompressed_size = std::cmp::min(
            self.remaining_decompressed,
            (num_blocks as u64) * 1024 * 1024,
        ) as usize;
        self.remaining_decompressed -= decompressed_size as u64;

        Ok(Some((decompressed_size, buffer)))
    }
}

/// Reader state that produces decompressed byte chunks from an LZ4 stream.
struct Lz4DecompressedSliceIterator<'r, R> {
    reader: &'r mut R,
    block_max_size: usize,
    slice_max_bytes: usize,
    leftover: Vec<u8>,
    started: bool,
    finished: bool,
}

impl<'r, R: AsyncRead + AsyncSeek + Unpin> Lz4DecompressedSliceIterator<'r, R> {
    async fn next_slice(&mut self) -> Option<io::Result<Vec<u8>>> {
        match self.try_next_slice().await {
            Ok(Some(slice)) => Some(Ok(slice)),
            Ok(None) => None,
            Err(e) => {
                self.finished = true;
                self.leftover.clear();
                Some(Err(e))
            }
        }
    }

    async fn try_next_slice(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.finished && self.leftover.is_empty() {
            return Ok(None);
        }
        if !self.started {
            self.reader
                .seek(SeekFrom::Start(LZ4_HEADER_SIZE as u64))
                .await?;
            self.started = true;
        }

        let mut buffer = Vec::with_capacity(self.slice_max_bytes);

        // Drain any leftover decompressed bytes from a previous block
        let take = self.slice_max_bytes.min(self.leftover.len());
        buffer.extend(self.leftover.drain(..take));

        let mut block_buf = Vec::new();

        while buffer.len() < self.slice_max_bytes && !self.finished {
            let mut size_bytes = [0u8; 4];
            self.reader.read_exact(&mut size_bytes).await?;

            let block_size = u32::from_le_bytes(size_bytes);
            if block_size == 0 {
                // EndMark reached
                self.finished = true;
                break;
            }

            let is_uncompressed = (block_size & 0x8000_0000) != 0;
            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            block_buf.resize(data_size, 0);
            self.reader.read_exact(&mut block_buf).await?;

            let decomp = if is_uncompressed {
                Cow::Borrowed(&block_buf[..])
            } else {
                let decomp = lz4_flex::block::decompress(&block_buf, self.block_max_size)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Cow::Owned(decomp)
            };

            let needed = self.slice_max_bytes - buffer.len();
            if decomp.len() <= needed {
                buffer.extend_from_slice(&decomp);
            } else {
                buffer.extend_from_slice(&decomp[..needed]);
                self.leftover.extend_from_slice(&decomp[needed..]);
                break;
            }
        }

        if buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(buffer))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlashProgress;
    use fast_md5::Md5;
    use futures::io::Cursor;
    use std::fmt::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    #[derive(Clone)]
    struct TestProgress {
        started_total: Arc<AtomicU64>,
        inc_bytes: Arc<AtomicU64>,
        ended: Arc<AtomicBool>,
        failed: Arc<AtomicBool>,
    }

    impl TestProgress {
        fn new() -> Self {
            Self {
                started_total: Arc::new(AtomicU64::new(0)),
                inc_bytes: Arc::new(AtomicU64::new(0)),
                ended: Arc::new(AtomicBool::new(false)),
                failed: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl FlashProgress for TestProgress {
        fn set_length(&self, _len: u64) {}

        fn inc(&self, bytes: u64) {
            self.inc_bytes.fetch_add(bytes, Ordering::Relaxed);
        }

        fn on_event(&self, event: FlashEvent<'_>) {
            match event {
                FlashEvent::Md5Start {
                    size: total_bytes, ..
                } => {
                    self.started_total.store(total_bytes, Ordering::Relaxed);
                }
                FlashEvent::Md5End(_) => {
                    self.ended.store(true, Ordering::Relaxed);
                }
                FlashEvent::Md5Fail(_) => {
                    self.failed.store(true, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_verify_md5_footer_success() {
        let _guard = crate::progress::TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Construct a synthetic TAR payload with zeroes padding and MD5 footer
        let payload = b"Hello, Odin TAR payload with some content!";
        let mut data = Vec::new();
        data.extend_from_slice(payload);
        // Null byte separating payload from MD5 footer text
        data.push(0);

        let mut hasher = Md5::new();
        hasher.update(&data);
        let digest = hasher.finalize();

        let hex_str = digest.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{:02x}", b);
            s
        });
        let footer = format!("{}  test.tar\n", hex_str);
        data.extend_from_slice(footer.as_bytes());

        let progress = TestProgress::new();
        crate::progress::set_progress(progress.clone());
        let res = pollster::block_on(verify_md5_footer(Cursor::new(&data), "test.tar"));
        crate::progress::clear_progress();

        assert!(res.is_ok());
        let expected_total = (payload.len() + 1) as u64;
        assert_eq!(
            progress.started_total.load(Ordering::Relaxed),
            expected_total
        );
        assert_eq!(progress.inc_bytes.load(Ordering::Relaxed), expected_total);
        assert!(progress.ended.load(Ordering::Relaxed));
        assert!(!progress.failed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_verify_md5_footer_corruption() {
        let _guard = crate::progress::TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let payload = b"Hello, Odin TAR payload with some content!";
        let mut data = Vec::new();
        data.extend_from_slice(payload);
        data.push(0);

        // Intentionally wrong hash
        let footer = "0123456789abcdef0123456789abcdef  test.tar\n";
        data.extend_from_slice(footer.as_bytes());

        let progress = TestProgress::new();
        crate::progress::set_progress(progress.clone());
        let res = pollster::block_on(verify_md5_footer(Cursor::new(&data), "test.tar"));
        crate::progress::clear_progress();

        assert!(res.is_err());
        assert!(progress.failed.load(Ordering::Relaxed));
        assert!(!progress.ended.load(Ordering::Relaxed));
    }

    #[test]
    fn test_lz4_decompressed_slices_reseek_and_truncation() {
        use futures::StreamExt;
        use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
        use std::io::Write;

        // 150 KB payload spanning 3 independent 64 KB LZ4 blocks (64K + 64K + 22K)
        let original: Vec<u8> = (0..150 * 1024).map(|i| (i % 251) as u8).collect();

        let mut frame_info = FrameInfo::new();
        frame_info.block_mode = BlockMode::Independent;
        frame_info.block_size = BlockSize::Max64KB;
        frame_info.content_size = Some(original.len() as u64);

        let mut encoder = FrameEncoder::with_frame_info(frame_info, Vec::new());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let pit_entry = PitEntry {
            binary_type: samloader_pit::BinaryType::ApplicationProcessor,
            device_type: samloader_pit::DeviceType::MMC,
            partition_id: 1,
            attributes: Default::default(),
            update_attributes: Default::default(),
            start_block: 0,
            block_count: 0,
            file_offset: 0,
            file_size: 0,
            partition_name: Default::default(),
            flash_filename: Default::default(),
            fota_filename: Default::default(),
        };

        pollster::block_on(async {
            let mut cursor = futures::io::Cursor::new(compressed.as_slice());
            let header = Lz4FrameHeader::parse(&mut cursor).await.unwrap();
            assert_eq!(header.content_size, original.len() as u64);
            assert_eq!(header.block_max_size, 64 * 1024);

            let mut lz4_file = FirmwareLz4File {
                pit_entry: &pit_entry,
                file: cursor,
                size: compressed.len() as u64,
                header,
            };

            // 1. Read a partial prefix and drop the stream (simulating inspect_super_firmware_info)
            let prefix = std::pin::pin!(lz4_file.decompressed_slices(10 * 1024))
                .next()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(prefix, &original[..10 * 1024]);

            // 2. Consume full stream with a 50 KB slice limit (unaligned with 64 KB blocks,
            // exercising both SeekFrom::Start(LZ4_HEADER_SIZE) rewind and leftover buffering)
            let mut reassembled = Vec::new();
            {
                let mut slices = std::pin::pin!(lz4_file.decompressed_slices(50 * 1024));
                while let Some(res) = slices.next().await {
                    let slice = res.unwrap();
                    assert!(slice.len() <= 50 * 1024);
                    reassembled.extend_from_slice(&slice);
                }
            }
            assert_eq!(reassembled, original);

            // 3. Truncated LZ4 stream must yield Err rather than silently ending with Ok
            let truncated = &compressed[..compressed.len() - 10];
            lz4_file.file = futures::io::Cursor::new(truncated);
            lz4_file.size = truncated.len() as u64;
            let results: Vec<io::Result<Vec<u8>>> =
                lz4_file.decompressed_slices(50 * 1024).collect().await;
            assert!(results.iter().any(|r| r.is_err()));
        });
    }
}
