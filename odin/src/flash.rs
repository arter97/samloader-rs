// Copyright 2026 John "topjohnwu" Wu
// Copyright 2021-2024 Henrik Grimler
// Copyright 2010-2017 Benjamin Dobell, Glass Echidna
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

use crate::FlashError;
use crate::avb;
use crate::firmware::{
    FirmwareFile, FirmwareInfo, FirmwareLz4File, Lz4FrameHeader, verify_md5_footer,
};
use crate::lp::inspect_super_firmware_info;
use crate::odin::OdinSession;
use crate::progress::{self, FlashEvent};
use futures::io::{AllowStdIo, AsyncRead, AsyncSeek, Cursor};
use memmap2::{Mmap, MmapOptions};
use samloader_pit::{PitData, PitEntry};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use tar::Archive;

struct IndexedEntry<'a> {
    original_name: String,
    normalized_name: String,
    file: &'a File,
    offset: u64,
    size: u64,
    is_lz4: bool,
}

impl<'a> IndexedEntry<'a> {
    fn map(&self) -> Result<Mmap, FlashError> {
        // SAFETY: The archive file is opened read-only and is assumed not to be
        // concurrently modified or truncated during the flashing operation.
        let mmap = unsafe {
            MmapOptions::new()
                .offset(self.offset)
                .len(self.size as usize)
                .map(self.file)
        }
        .map_err(|e| FlashError::MmapFailed(self.original_name.clone(), e))?;
        Ok(mmap)
    }
}

fn anon_mmap(data: &[u8]) -> std::io::Result<Mmap> {
    let mut mapping = MmapOptions::new().len(data.len()).map_anon()?;
    mapping.copy_from_slice(data);
    mapping.make_read_only()
}

fn normalize_basename(path_str: &str) -> (String, bool) {
    let mut filename = Path::new(path_str)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    if filename.to_lowercase().ends_with(".lz4") {
        filename.truncate(filename.len() - 4);
        (filename, true)
    } else {
        (filename, false)
    }
}

fn find_pit_entry_by_filename<'a>(pit_data: &'a PitData, filename: &str) -> Option<&'a PitEntry> {
    pit_data.entries.iter().find(|e| {
        let flash_fn = e.flash_filename.to_string_lossy();
        flash_fn.eq_ignore_ascii_case(filename)
    })
}

fn is_super_entry(entry: &PitEntry) -> bool {
    entry.partition_name == "SUPER"
        || entry
            .flash_filename
            .to_string_lossy()
            .eq_ignore_ascii_case("super.img")
}

// Mirrors fastboot, where partitions with a prefix (e.g. guest_vbmeta_a) also count
fn is_vbmeta_entry(entry: &PitEntry) -> bool {
    let name = entry.partition_name.to_string_lossy().to_ascii_uppercase();
    ["VBMETA", "VBMETA_A", "VBMETA_B"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn is_boot_entry(entry: &PitEntry) -> bool {
    let name = entry.partition_name.to_string_lossy();
    ["BOOT", "BOOT_A", "BOOT_B"]
        .iter()
        .any(|boot| name.eq_ignore_ascii_case(boot))
}

// A skip target matches either the flash filename or the partition name of a PIT
// entry. Partition names also match their _A and _B slots on A/B devices.
fn is_skip_target(entry: &PitEntry, target: &str) -> bool {
    let (filename, _) = normalize_basename(target);
    if entry
        .flash_filename
        .to_string_lossy()
        .eq_ignore_ascii_case(&filename)
    {
        return true;
    }

    let name = entry.partition_name.to_string_lossy();
    ["", "_A", "_B"]
        .iter()
        .any(|slot| name.eq_ignore_ascii_case(&format!("{}{}", target, slot)))
}

async fn create_firmware_info<'a, R: AsyncRead + AsyncSeek + Unpin>(
    mut file: R,
    source_size: u64,
    is_lz4_suffix: bool,
    pit_entry: &'a PitEntry,
    skip_size_check: bool,
    file_display_name: &str,
) -> Result<FirmwareInfo<'a, R>, FlashError> {
    let lz4_frame_header = if is_lz4_suffix {
        match Lz4FrameHeader::parse(&mut file).await {
            Ok(fh) => Some(fh),
            Err(e) => {
                return Err(FlashError::Lz4Header(file_display_name.to_string(), e));
            }
        }
    } else {
        None
    };

    if !skip_size_check {
        let partition_size = pit_entry.partition_size();
        let check_size = if let Some(fh) = &lz4_frame_header {
            fh.content_size
        } else {
            source_size
        };

        if partition_size > 0 && check_size > partition_size {
            return Err(FlashError::PartitionTooSmall(
                pit_entry.partition_name.to_string_lossy().into_owned(),
            ));
        }
    }

    if let Some(header) = lz4_frame_header {
        Ok(FirmwareInfo::Lz4(FirmwareLz4File {
            pit_entry,
            file,
            size: source_size,
            header,
        }))
    } else {
        Ok(FirmwareInfo::Normal(FirmwareFile {
            pit_entry,
            file,
            size: source_size,
        }))
    }
}

/// Specifies the device reboot behavior after a flash session concludes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum RebootMode {
    /// Do not reboot the device; end the session and remain in download mode.
    #[default]
    None,
    /// Reboot the device normally out of Download Mode.
    Normal,
    /// Reboot the device back into Download Mode.
    Download,
}

/// Orchestrates the flashing pipeline, processing package and partition sources
/// and executing the Loke flash protocol.
pub struct FlashManager<'a> {
    session: &'a mut OdinSession,
    pit_file_bytes: Option<Vec<u8>>,

    reboot_mode: RebootMode,
    skip_size_check: bool,
    skip_md5: bool,
    pit_path: Option<&'a str>,
    packages: Vec<String>,
    partitions: Vec<(Option<String>, String)>,
    super_used_size: Option<u32>,
    has_download_list: bool,
    sales_code: Option<&'a str>,
    erase: bool,
    skip: Vec<String>,
    vbmeta_flags: u32,
}

impl<'a> FlashManager<'a> {
    /// Creates a new `FlashManager` associated with an active `OdinSession`.
    pub fn new(session: &'a mut OdinSession) -> Self {
        Self {
            session,
            pit_file_bytes: None,
            reboot_mode: RebootMode::None,
            skip_size_check: false,
            skip_md5: false,
            pit_path: None,
            packages: Vec::new(),
            partitions: Vec::new(),
            super_used_size: None,
            has_download_list: false,
            sales_code: None,
            erase: false,
            skip: Vec::new(),
            vbmeta_flags: 0,
        }
    }

    /// Sets whether to perform a low-level NAND hardware erase on the `USERDATA` partition
    /// prior to flashing or as a standalone wipe operation.
    pub fn erase(mut self, enabled: bool) -> Self {
        self.erase = enabled;
        self
    }

    /// Sets an optional 3-letter CSC / Sales Code to configure on the device.
    pub fn sales_code(mut self, sales_code: Option<&'a str>) -> Self {
        self.sales_code = sales_code;
        self
    }

    /// Sets the reboot mode to perform after flashing completes.
    pub fn reboot_mode(mut self, mode: RebootMode) -> Self {
        self.reboot_mode = mode;
        self
    }

    /// Sets whether to automatically reboot normally out of Download Mode after flashing.
    pub fn auto_reboot(mut self, enabled: bool) -> Self {
        self.reboot_mode = if enabled {
            RebootMode::Normal
        } else {
            RebootMode::None
        };
        self
    }

    /// Sets whether to reboot the device back into Download Mode after flashing.
    pub fn redownload(mut self, enabled: bool) -> Self {
        if enabled {
            self.reboot_mode = RebootMode::Download;
        }
        self
    }

    /// Sets whether to skip partition size checks.
    pub fn skip_size_check(mut self, enabled: bool) -> Self {
        self.skip_size_check = enabled;
        self
    }

    /// Sets whether to skip MD5 package verification.
    pub fn skip_md5(mut self, enabled: bool) -> Self {
        self.skip_md5 = enabled;
        self
    }

    /// Sets an explicit PIT file path.
    pub fn pit(mut self, pit_path: &'a str) -> Self {
        self.pit_path = Some(pit_path);
        self
    }

    /// Sets the list of TAR packages to flash.
    pub fn packages(mut self, packages: &[impl AsRef<str>]) -> Self {
        self.packages = packages.iter().map(|p| p.as_ref().to_string()).collect();
        self
    }

    /// Sets the list of individual partition files to flash.
    pub fn partitions(mut self, partitions: &[(Option<String>, String)]) -> Self {
        self.partitions = partitions.to_vec();
        self
    }

    /// Sets the partitions to exclude from flashing. Each target is either a file name
    /// or a partition name in the PIT. Partition names also exclude their `_A` and `_B`
    /// slots.
    pub fn skip(mut self, targets: &[impl AsRef<str>]) -> Self {
        self.skip = targets
            .iter()
            .map(|t| t.as_ref().trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        self
    }

    /// Sets whether to disable dm-verity in the flashed vbmeta images, like fastboot's
    /// `--disable-verity`. Every partition named `VBMETA`, `VBMETA_A` or `VBMETA_B`
    /// (optionally with a prefix) is rewritten, and LZ4 compressed images are sent
    /// decompressed. Devices without a vbmeta partition have `BOOT` rewritten instead.
    pub fn disable_verity(mut self, enabled: bool) -> Self {
        self.set_vbmeta_flag(avb::AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED, enabled);
        self
    }

    /// Sets whether to disable AVB verification in the flashed vbmeta images, like
    /// fastboot's `--disable-verification`. The same images as with
    /// [`disable_verity`](Self::disable_verity) are rewritten.
    pub fn disable_verification(mut self, enabled: bool) -> Self {
        self.set_vbmeta_flag(avb::AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED, enabled);
        self
    }

    fn set_vbmeta_flag(&mut self, flag: u32, enabled: bool) {
        if enabled {
            self.vbmeta_flags |= flag;
        } else {
            self.vbmeta_flags &= !flag;
        }
    }

    /// Executes the flashing pipeline sequence.
    pub async fn execute(&mut self) -> Result<(), FlashError> {
        // Step 0: Set device sales code if configured
        if let Some(sales_code) = self.sales_code {
            progress::println(&format!("Setting device sales code to {}...", sales_code));
            self.session.set_sales_code(sales_code).await?;
        }

        // If no packages, partitions, or explicit PIT are specified, complete session and return
        if self.packages.is_empty() && self.partitions.is_empty() && self.pit_path.is_none() {
            if self.erase {
                self.session.nand_erase().await?;
            }
            match self.reboot_mode {
                RebootMode::Normal => self.session.reboot_device().await?,
                RebootMode::Download => self.session.reboot_to_download().await?,
                RebootMode::None => self.session.end_session().await?,
            }
            return Ok(());
        }

        // Step 1: Resolve explicit PIT file if provided
        if let Some(pit_path) = self.pit_path {
            let mut f = File::open(pit_path)
                .map_err(|e| FlashError::FileOpenFailed(pit_path.to_string(), e))?;
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer)
                .map_err(|e| FlashError::FileReadFailed(pit_path.to_string(), e))?;
            self.pit_file_bytes = Some(buffer);
        }

        // Step 2: Open packages and scan TAR containers to index entries
        let opened_packages = self.open_and_verify_packages().await?;
        let resolved_entries = self.scan_tar_packages(&opened_packages)?;

        // Step 3: Flash PIT if available and download active PIT data from the device
        let pit_data = self.download_and_parse_pit().await?;

        // Step 4: Resolve the partitions excluded from flashing
        let skipped_ids = self.resolve_skipped_partitions(&pit_data)?;

        // The super size check is meaningless when super is not flashed
        if pit_data
            .entries
            .iter()
            .any(|e| skipped_ids.contains(&e.partition_id) && is_super_entry(e))
        {
            self.super_used_size = None;
        }

        // Step 5: Map entries and individual files to FirmwareInfo payloads
        let mut partition_infos = self
            .build_partition_infos(
                &pit_data,
                resolved_entries,
                &self.partitions,
                &skipped_ids,
                self.skip_size_check,
            )
            .await?;

        // Step 6: Rewrite vbmeta flags if requested
        self.rewrite_vbmeta_payloads(&pit_data, &mut partition_infos)
            .await?;

        // Auto-detect super_used_size if not specified in TAR metadata
        if self.super_used_size.is_none()
            && let Some(super_info) = partition_infos.iter_mut().find(|info| {
                let entry = match info {
                    FirmwareInfo::Normal(f) => f.pit_entry,
                    FirmwareInfo::Lz4(f) => f.pit_entry,
                };
                is_super_entry(entry)
            })
        {
            self.super_used_size = inspect_super_firmware_info(super_info).await;
        }

        // Step 7: Flash payloads to the device
        self.flash_partitions(partition_infos, self.reboot_mode)
            .await?;

        Ok(())
    }

    // Helper 1: Open TAR packages and optionally verify MD5 footers
    async fn open_and_verify_packages(&self) -> Result<Vec<(String, File)>, FlashError> {
        if self.packages.is_empty() {
            return Ok(Vec::new());
        }

        let mut opened_packages = Vec::new();
        for pkg in &self.packages {
            let file = File::open(pkg).map_err(|e| FlashError::FileOpenFailed(pkg.clone(), e))?;
            opened_packages.push((pkg.clone(), file));
        }

        if !self.skip_md5 {
            for (pkg, file) in &mut opened_packages {
                if pkg.to_lowercase().ends_with(".md5") {
                    verify_md5_footer(AllowStdIo::new(&*file), pkg)
                        .await
                        .map_err(|e| FlashError::Md5VerificationFailed(pkg.clone(), e))?;

                    file.seek(SeekFrom::Start(0))
                        .map_err(|e| FlashError::FileSeekFailed(pkg.clone(), e))?;
                }
            }
        }

        Ok(opened_packages)
    }

    // Helper 2: Scan TAR packages to find resolved entries and pull package PIT if needed
    fn scan_tar_packages<'p>(
        &mut self,
        opened_packages: &'p [(String, File)],
    ) -> Result<Vec<IndexedEntry<'p>>, FlashError> {
        if opened_packages.is_empty() {
            return Ok(Vec::new());
        }

        // Scan and index TAR containers
        let mut archives_download_lists: Vec<HashSet<String>> = Vec::new();
        let mut all_packages_entries: Vec<Vec<IndexedEntry<'p>>> = Vec::new();

        for (pkg, file) in opened_packages {
            let mut archive = Archive::new(file);
            let entries = archive
                .entries_with_seek()
                .map_err(|e| FlashError::ArchiveReadFailed(pkg.clone(), e))?;

            let mut package_entries = Vec::new();

            for entry_res in entries {
                let entry = entry_res.map_err(|e| FlashError::ArchiveCorrupted(pkg.clone(), e))?;

                let entry_path = match entry.path() {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(_) => continue,
                };

                let offset = entry.raw_file_position();
                let size = entry.size();

                let (normalized_name, is_lz4) = normalize_basename(&entry_path);

                if normalized_name == "download-list.txt" {
                    // Read the allowlist manifest
                    let mut reader = entry;
                    let mut content = String::new();
                    reader
                        .read_to_string(&mut content)
                        .map_err(|e| FlashError::ArchiveCorrupted(pkg.clone(), e))?;

                    self.has_download_list = true;
                    let download_list = content
                        .lines()
                        .filter_map(|s| {
                            let s = s.trim();
                            if s.is_empty() {
                                None
                            } else {
                                Some(s.to_string())
                            }
                        })
                        .collect();
                    archives_download_lists.push(download_list);
                } else if normalized_name == "super_used_size.txt" {
                    let mut reader = entry;
                    let mut content = String::new();
                    reader
                        .read_to_string(&mut content)
                        .map_err(|e| FlashError::ArchiveCorrupted(pkg.clone(), e))?;
                    let val = content.trim().parse::<u32>().map_err(|e| {
                        FlashError::ArchiveCorrupted(
                            pkg.clone(),
                            std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                        )
                    })?;
                    self.super_used_size = Some(val);
                } else {
                    package_entries.push(IndexedEntry {
                        original_name: entry_path,
                        normalized_name,
                        file,
                        offset,
                        size,
                        is_lz4,
                    });
                }
            }

            all_packages_entries.push(package_entries);
        }

        // If any package contained a manifest, we use it as our global download allowlist
        let download_allowlist = if let Some((first, rest)) = archives_download_lists.split_first()
        {
            // Cross-archive manifest consistency check
            if !rest.iter().all(|m| m == first) {
                return Err(FlashError::CrossArchiveInconsistency);
            }
            Some(first)
        } else {
            None
        };

        let mut resolved_entries: Vec<IndexedEntry<'p>> = Vec::new();
        let mut pit_entry: Option<IndexedEntry<'p>> = None;

        // Apply manifest filtering and positional precedence (last-writer-wins)
        for package_entries in all_packages_entries {
            for entry in package_entries {
                if entry.normalized_name.ends_with(".pit") {
                    pit_entry = Some(entry);
                } else if let Some(allowlist) = download_allowlist {
                    if allowlist.contains(&entry.normalized_name) {
                        resolved_entries.push(entry);
                    } else {
                        progress::println(&format!(
                            "Skipping {} (not in download-list.txt)",
                            entry.original_name
                        ));
                    }
                } else {
                    resolved_entries.push(entry);
                }
            }
        }

        // Extract PIT local bytes if any from TAR archives and set internal field if still None
        if self.pit_file_bytes.is_none()
            && let Some(entry) = pit_entry
        {
            let mmap = entry.map()?;
            self.pit_file_bytes = Some(mmap.to_vec());
        }

        Ok(resolved_entries)
    }

    // Helper 3: Flash PIT if available and download active PIT data
    async fn download_and_parse_pit(&mut self) -> Result<PitData, FlashError> {
        if self.erase {
            self.session.nand_erase().await?;
        }

        if let Some(pit_bytes) = &self.pit_file_bytes {
            progress::println("Flashing PIT");
            self.session.send_pit_info(pit_bytes).await?;
            progress::println("PIT flash successful\n");
        }

        progress::println("Downloading device's PIT file");
        let pit_buffer = self.session.receive_pit_info().await?;

        let pit_data = PitData::new(&pit_buffer).map_err(FlashError::PitUnpackFailed)?;
        Ok(pit_data)
    }

    // Helper 4: Resolve skip targets into the IDs of the PIT entries they match
    fn resolve_skipped_partitions(&self, pit_data: &PitData) -> Result<HashSet<u32>, FlashError> {
        let mut skipped_ids = HashSet::new();
        for target in &self.skip {
            let mut matched = false;
            for entry in &pit_data.entries {
                if is_skip_target(entry, target) {
                    skipped_ids.insert(entry.partition_id);
                    matched = true;
                }
            }
            if !matched {
                return Err(FlashError::SkipTargetNotFound(target.clone()));
            }
        }
        Ok(skipped_ids)
    }

    // Helper 5: Map package entries and individual files into FirmwareInfo
    async fn build_partition_infos<'c>(
        &self,
        pit_data: &'c PitData,
        resolved_entries: Vec<IndexedEntry<'_>>,
        partitions: &[(Option<String>, String)],
        skipped_ids: &HashSet<u32>,
        skip_size_check: bool,
    ) -> Result<Vec<FirmwareInfo<'c, Cursor<Mmap>>>, FlashError> {
        enum PartitionSource<'p> {
            Archive(IndexedEntry<'p>),
            File { path: String, is_lz4: bool },
        }

        struct PlannedPartition<'p, 'pit> {
            pit_entry: &'pit PitEntry,
            source: PartitionSource<'p>,
        }

        let mut planned_partitions = Vec::new();

        // 1. Collect candidate entries from TAR packages
        for entry in resolved_entries {
            let Some(pit_entry) = find_pit_entry_by_filename(pit_data, &entry.normalized_name)
            else {
                progress::println(&format!(
                    "Skipping orphan file \"{}\" (no matching partition in PIT)",
                    entry.original_name
                ));
                continue;
            };

            planned_partitions.push(PlannedPartition {
                pit_entry,
                source: PartitionSource::Archive(entry),
            });
        }

        // 2. Collect candidate individual files
        for (part_name, part_filename) in partitions {
            let (filename, is_lz4_suffix) = normalize_basename(part_filename);
            let entry = match part_name {
                None => {
                    let Some(entry) = find_pit_entry_by_filename(pit_data, &filename) else {
                        return Err(FlashError::PartitionNotFound(part_filename.clone()));
                    };
                    entry
                }
                Some(name) => {
                    if let Ok(id) = name.parse::<u32>() {
                        let Some(entry) = pit_data.find_entry_by_id(id) else {
                            return Err(FlashError::PartitionIdNotFound(id));
                        };
                        entry
                    } else {
                        let Some(entry) = pit_data.find_entry_by_name(name) else {
                            return Err(FlashError::PartitionNotFound(name.clone()));
                        };
                        entry
                    }
                }
            };

            planned_partitions.push(PlannedPartition {
                pit_entry: entry,
                source: PartitionSource::File {
                    path: part_filename.clone(),
                    is_lz4: is_lz4_suffix,
                },
            });
        }

        // 3. Partition deduplication: last writer wins
        let mut mapped_partition_ids = HashSet::new();
        let mut unique_planned = Vec::new();
        for planned in planned_partitions.into_iter().rev() {
            if mapped_partition_ids.insert(planned.pit_entry.partition_id) {
                unique_planned.push(planned);
            }
        }
        unique_planned.reverse();

        // 4. Drop partitions excluded with skip targets
        unique_planned.retain(|planned| {
            if skipped_ids.contains(&planned.pit_entry.partition_id) {
                progress::println(&format!(
                    "Skipping {} (excluded with --skip)",
                    planned.pit_entry.partition_name.to_string_lossy()
                ));
                false
            } else {
                true
            }
        });

        // 5. Lazily map and build FirmwareInfo only for unique planned partitions
        let mut unique_partition_infos = Vec::with_capacity(unique_planned.len());
        for planned in unique_planned {
            let (mmap, file_size, is_lz4, display_name) = match planned.source {
                PartitionSource::Archive(entry) => {
                    let mmap = entry.map()?;
                    (mmap, entry.size, entry.is_lz4, entry.original_name)
                }
                PartitionSource::File { path, is_lz4 } => {
                    let (mmap, file_size) = File::open(&path)
                        .and_then(|f| {
                            let file_size = f.metadata()?.len();
                            // SAFETY: The partition file is opened read-only and is assumed not to be
                            // concurrently modified or truncated during the flashing operation.
                            let mmap =
                                unsafe { MmapOptions::new().len(file_size as usize).map(&f)? };
                            Ok((mmap, file_size))
                        })
                        .map_err(|e| FlashError::MmapFailed(path.clone(), e))?;
                    (mmap, file_size, is_lz4, path)
                }
            };

            let info = create_firmware_info(
                Cursor::new(mmap),
                file_size,
                is_lz4,
                planned.pit_entry,
                skip_size_check,
                &display_name,
            )
            .await?;
            unique_partition_infos.push(info);
        }

        Ok(unique_partition_infos)
    }

    // Helper 6: Set the requested AVB flags in vbmeta payloads. Like fastboot, the
    // top-level vbmeta is looked up in boot on devices without a vbmeta partition.
    async fn rewrite_vbmeta_payloads(
        &self,
        pit_data: &PitData,
        partition_infos: &mut [FirmwareInfo<'_, Cursor<Mmap>>],
    ) -> Result<(), FlashError> {
        if self.vbmeta_flags == 0 {
            return Ok(());
        }

        let has_vbmeta_partition = pit_data.entries.iter().any(is_vbmeta_entry);
        let mut rewritten = false;
        for info in partition_infos.iter_mut() {
            let pit_entry = info.pit_entry();
            let in_footer = if is_vbmeta_entry(pit_entry) {
                false
            } else if !has_vbmeta_partition && is_boot_entry(pit_entry) {
                true
            } else {
                continue;
            };

            let name = pit_entry.partition_name.to_string_lossy();
            let rewrite_err = |e| FlashError::VbmetaRewriteFailed(name.to_string(), e);

            // The patched image is sent uncompressed, bypassing LZ4 passthrough
            let mut data = info.read_all().await.map_err(rewrite_err)?;
            let Some(offset) = avb::rewrite_vbmeta(&mut data, self.vbmeta_flags, in_footer)
                .map_err(rewrite_err)?
            else {
                continue;
            };

            progress::println(&format!(
                "Rewriting {} vbmeta struct at offset: {}",
                name, offset
            ));
            let size = data.len() as u64;
            let mmap = anon_mmap(&data).map_err(rewrite_err)?;
            *info = FirmwareInfo::Normal(FirmwareFile {
                pit_entry,
                file: Cursor::new(mmap),
                size,
            });
            rewritten = true;
        }

        if !rewritten {
            progress::println(
                "Warning: no vbmeta image is being flashed, AVB flags left unchanged",
            );
        }

        Ok(())
    }

    // Helper 7: Flash deduplicated partition payloads to the device
    async fn flash_partitions<R: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        partition_infos: Vec<FirmwareInfo<'_, R>>,
        reboot_mode: RebootMode,
    ) -> Result<(), FlashError> {
        let total_bytes: u64 = partition_infos
            .iter()
            .map(|part| match part {
                FirmwareInfo::Normal(f) => f.size,
                FirmwareInfo::Lz4(f) => f.header.content_size,
            })
            .sum();

        self.session.set_total_bytes(total_bytes).await?;

        if let Some(super_used_size) = self.super_used_size
            && super_used_size > 0
            && self.session.bootloader_protocol_version() >= 3
        {
            let check_size = if self.has_download_list || self.packages.is_empty() {
                super_used_size
            } else {
                0
            };
            progress::println("Checking available super partition size...");
            self.session
                .check_super_size(check_size)
                .await
                .map_err(FlashError::SuperSizeCheckFailed)?;
        }

        for info in partition_infos {
            let name = match &info {
                FirmwareInfo::Normal(f) => f.pit_entry.partition_name.to_string_lossy(),
                FirmwareInfo::Lz4(f) => f.pit_entry.partition_name.to_string_lossy(),
            };

            let partition_size = match &info {
                FirmwareInfo::Normal(f) => f.size,
                FirmwareInfo::Lz4(f) => f.header.content_size,
            };

            progress::on_event(FlashEvent::PartitionStart {
                name: &name,
                size: partition_size,
            });

            let res = match info {
                FirmwareInfo::Normal(mut f) => self.session.send_file(&mut f).await,
                FirmwareInfo::Lz4(mut f) => self.session.send_lz4_file(&mut f).await,
            };

            if let Err(e) = res {
                progress::on_event(FlashEvent::PartitionFail(&name));
                return Err(FlashError::Odin(e));
            }

            progress::on_event(FlashEvent::PartitionEnd(&name));
        }

        self.session.end_session().await?;

        match reboot_mode {
            RebootMode::Normal => {
                self.session.reboot_device().await?;
            }
            RebootMode::Download => {
                self.session.reboot_to_download().await?;
            }
            RebootMode::None => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::odin::OdinConnection;
    use crate::usb::MockBackend;

    #[test]
    fn test_scan_tar_packages_metadata_and_manifest() {
        let temp_dir = std::env::temp_dir().join("samloader_test_tar");
        let _ = std::fs::create_dir_all(&temp_dir);
        let tar_path = temp_dir.join("test_package.tar");

        {
            let tar_file = File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(tar_file);

            // 1. Add meta-data/super_used_size.txt
            let mut header = tar::Header::new_gnu();
            let size_content = b"27276104\n";
            header.set_size(size_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "meta-data/super_used_size.txt",
                    &size_content[..],
                )
                .unwrap();

            // 2. Add meta-data/download-list.txt
            let mut header = tar::Header::new_gnu();
            let list_content = b"boot.img\n";
            header.set_size(list_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "meta-data/download-list.txt",
                    &list_content[..],
                )
                .unwrap();

            // 3. Add boot.img
            let mut header = tar::Header::new_gnu();
            let boot_content = b"DUMMY BOOT IMAGE DATA";
            header.set_size(boot_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "boot.img", &boot_content[..])
                .unwrap();

            builder.finish().unwrap();
        }

        pollster::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let tar_file = File::open(&tar_path).unwrap();
            let opened_packages = vec![(tar_path.to_string_lossy().to_string(), tar_file)];

            let mut manager = FlashManager::new(&mut session);
            let resolved = manager.scan_tar_packages(&opened_packages).unwrap();

            assert_eq!(manager.super_used_size, Some(27276104));
            assert!(manager.has_download_list);
            assert_eq!(resolved.len(), 1);
            assert_eq!(resolved[0].normalized_name, "boot.img");
        });

        let _ = std::fs::remove_file(tar_path);
        let _ = std::fs::remove_dir(temp_dir);
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_success() {
        pollster::block_on(async {
            let backend = Box::new(MockBackend::new().with_protocol_version(3));
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session);
            manager.super_used_size = Some(27276104);
            manager.has_download_list = true;

            assert!(
                manager
                    .flash_partitions(
                        Vec::<FirmwareInfo<'_, Cursor<&[u8]>>>::new(),
                        RebootMode::None
                    )
                    .await
                    .is_ok()
            );
        });
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_rejection() {
        pollster::block_on(async {
            let backend = Box::new(
                MockBackend::new()
                    .with_protocol_version(3)
                    .with_fail_check_super_size(-1),
            );
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session);
            manager.super_used_size = Some(27276104);
            manager.has_download_list = true;

            let res = manager
                .flash_partitions(
                    Vec::<FirmwareInfo<'_, Cursor<&[u8]>>>::new(),
                    RebootMode::None,
                )
                .await;
            assert!(matches!(res, Err(FlashError::SuperSizeCheckFailed(_))));
        });
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_skipped_on_legacy_protocol() {
        pollster::block_on(async {
            // Even if fail_check_super_size is set, legacy protocol version 2 must skip opcode 0x6a
            let backend = Box::new(
                MockBackend::new()
                    .with_protocol_version(2)
                    .with_fail_check_super_size(-1),
            );
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session);
            manager.super_used_size = Some(27276104);
            manager.has_download_list = true;

            assert!(
                manager
                    .flash_partitions(
                        Vec::<FirmwareInfo<'_, Cursor<&[u8]>>>::new(),
                        RebootMode::None
                    )
                    .await
                    .is_ok()
            );
        });
    }

    #[test]
    fn test_scan_tar_packages_corrupt_manifest_fails() {
        let temp_dir = std::env::temp_dir().join("samloader_test_tar_corrupt_manifest");
        let _ = std::fs::create_dir_all(&temp_dir);
        let tar_path = temp_dir.join("corrupt_manifest.tar");

        {
            let tar_file = File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(tar_file);

            // Add meta-data/download-list.txt with invalid UTF-8 bytes
            let mut header = tar::Header::new_gnu();
            let corrupt_content = [0xFF, 0xFE, 0xFD];
            header.set_size(corrupt_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "meta-data/download-list.txt",
                    &corrupt_content[..],
                )
                .unwrap();

            builder.finish().unwrap();
        }

        pollster::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let tar_file = File::open(&tar_path).unwrap();
            let opened_packages = vec![(tar_path.to_string_lossy().to_string(), tar_file)];

            let mut manager = FlashManager::new(&mut session);
            let result = manager.scan_tar_packages(&opened_packages);

            assert!(matches!(result, Err(FlashError::ArchiveCorrupted(_, _))));
        });

        let _ = std::fs::remove_file(tar_path);
        let _ = std::fs::remove_dir(temp_dir);
    }

    #[test]
    fn test_download_and_parse_pit_flashes_available_pit() {
        pollster::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session);
            manager.pit_file_bytes = Some(
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/test-data/M3_EUR_OPEN_4G.pit"
                ))
                .to_vec(),
            );

            let pit_data = manager.download_and_parse_pit().await.unwrap();
            // M3_EUR_OPEN_4G.pit has Mx-MDM, verifying PIT was sent and updated device state
            assert_eq!(pit_data.cpu_bl_id.to_string_lossy(), "Mx-MDM");
        });
    }

    fn ab_pit_data() -> PitData {
        PitData::new(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/Q7MQ_EUR_OPENX.pit"
        )))
        .unwrap()
    }

    fn skipped_names(targets: &[&str]) -> Result<Vec<String>, FlashError> {
        pollster::block_on(async {
            let pit_data = ab_pit_data();
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let manager = FlashManager::new(&mut session).skip(targets);
            let skipped_ids = manager.resolve_skipped_partitions(&pit_data)?;
            let mut names: Vec<String> = pit_data
                .entries
                .iter()
                .filter(|e| skipped_ids.contains(&e.partition_id))
                .map(|e| e.partition_name.to_string_lossy().into_owned())
                .collect();
            names.sort();
            Ok(names)
        })
    }

    #[test]
    fn test_skip_partition_name_covers_ab_slots() {
        assert_eq!(skipped_names(&["BOOT"]).unwrap(), ["BOOT_A", "BOOT_B"]);
        assert_eq!(
            skipped_names(&["vbmeta"]).unwrap(),
            ["VBMETA_A", "VBMETA_B"]
        );
        assert_eq!(skipped_names(&["boot_b"]).unwrap(), ["BOOT_B"]);
        assert_eq!(skipped_names(&["SUPER"]).unwrap(), ["SUPER"]);
    }

    #[test]
    fn test_skip_file_name_covers_all_matching_partitions() {
        assert_eq!(skipped_names(&["boot.img"]).unwrap(), ["BOOT_A", "BOOT_B"]);
        assert_eq!(
            skipped_names(&["AP/vbmeta.img.lz4"]).unwrap(),
            ["VBMETA_A", "VBMETA_B"]
        );
        assert_eq!(
            skipped_names(&["init_boot.img", "DTBO", " "]).unwrap(),
            ["DTBO_A", "DTBO_B", "INIT_BOOT_A", "INIT_BOOT_B"]
        );
    }

    #[test]
    fn test_skip_unknown_target_fails() {
        assert!(matches!(
            skipped_names(&["BOOT", "nonexistent.img"]),
            Err(FlashError::SkipTargetNotFound(t)) if t == "nonexistent.img"
        ));
    }

    #[test]
    fn test_build_partition_infos_drops_skipped_partitions() {
        let temp_dir = std::env::temp_dir().join("samloader_test_skip_build");
        let _ = std::fs::create_dir_all(&temp_dir);
        let mut partitions = Vec::new();
        for name in ["boot.img", "vbmeta.img", "dtbo.img"] {
            let path = temp_dir.join(name);
            std::fs::write(&path, b"DUMMY IMAGE DATA").unwrap();
            partitions.push((None, path.to_string_lossy().into_owned()));
        }
        partitions.push((
            Some("VBMETA_B".to_string()),
            temp_dir.join("vbmeta.img").to_string_lossy().into_owned(),
        ));

        pollster::block_on(async {
            let pit_data = ab_pit_data();
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let manager = FlashManager::new(&mut session).skip(&["boot.img", "VBMETA"]);
            let skipped_ids = manager.resolve_skipped_partitions(&pit_data).unwrap();
            let infos = manager
                .build_partition_infos(&pit_data, Vec::new(), &partitions, &skipped_ids, false)
                .await
                .unwrap();

            let names: Vec<String> = infos
                .iter()
                .map(|info| match info {
                    FirmwareInfo::Normal(f) => f.pit_entry.partition_name.to_string_lossy(),
                    FirmwareInfo::Lz4(f) => f.pit_entry.partition_name.to_string_lossy(),
                })
                .map(|n| n.into_owned())
                .collect();
            assert_eq!(names, ["DTBO_A"]);
        });

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_execute_skipping_super_skips_super_size_check() {
        let temp_dir = std::env::temp_dir().join("samloader_test_skip_super");
        let _ = std::fs::create_dir_all(&temp_dir);
        let tar_path = temp_dir.join("AP.tar");

        {
            let tar_file = File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(tar_file);
            let files: [(&str, &[u8]); 4] = [
                ("meta-data/super_used_size.txt", b"27276104\n"),
                ("meta-data/download-list.txt", b"boot.img\nsuper.img\n"),
                ("boot.img", b"DUMMY BOOT IMAGE DATA"),
                ("super.img", b"DUMMY SUPER IMAGE DATA"),
            ];
            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, content).unwrap();
            }
            builder.finish().unwrap();
        }

        let run = |skip: &[&str]| {
            pollster::block_on(async {
                let backend = Box::new(
                    MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b())
                        .with_protocol_version(3)
                        .with_fail_check_super_size(-1),
                );
                let mut connection = OdinConnection::new(backend);
                connection.init().await.unwrap();
                let mut session = connection.begin_session().await.unwrap();
                FlashManager::new(&mut session)
                    .packages(&[tar_path.to_string_lossy()])
                    .skip(skip)
                    .execute()
                    .await
            })
        };

        assert!(matches!(run(&[]), Err(FlashError::SuperSizeCheckFailed(_))));
        assert!(run(&["super.img"]).is_ok());

        let _ = std::fs::remove_dir_all(temp_dir);
    }
    fn anon_mapping(data: &[u8]) -> Cursor<Mmap> {
        Cursor::new(anon_mmap(data).unwrap())
    }

    fn lz4_mapping(data: &[u8]) -> (Cursor<Mmap>, u64, Lz4FrameHeader) {
        use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
        use std::io::Write;

        let info = FrameInfo::new()
            .content_size(Some(data.len() as u64))
            .block_size(BlockSize::Max1MB)
            .block_mode(BlockMode::Independent);
        let mut encoder = FrameEncoder::with_frame_info(info, Vec::new());
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();
        let size = compressed.len() as u64;
        let header =
            pollster::block_on(Lz4FrameHeader::parse(Cursor::new(&compressed[..]))).unwrap();
        (anon_mapping(&compressed), size, header)
    }

    fn find_entry<'p>(pit_data: &'p PitData, name: &str) -> &'p PitEntry {
        pit_data.find_entry_by_name(name).unwrap()
    }

    fn rewrite_vbmeta(
        pit_data: &PitData,
        infos: &mut [FirmwareInfo<'_, Cursor<Mmap>>],
        verity: bool,
        verification: bool,
    ) -> Result<(), FlashError> {
        pollster::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            FlashManager::new(&mut session)
                .disable_verity(verity)
                .disable_verification(verification)
                .rewrite_vbmeta_payloads(pit_data, infos)
                .await
        })
    }

    fn normal_bytes(info: &FirmwareInfo<'_, Cursor<Mmap>>) -> Vec<u8> {
        match info {
            FirmwareInfo::Normal(f) => f.file.get_ref().to_vec(),
            FirmwareInfo::Lz4(_) => panic!("expected an uncompressed payload"),
        }
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_patches_all_vbmeta() {
        use crate::avb::tests::{vbmeta_flags, vbmeta_image};

        let pit_data = ab_pit_data();
        let image = vbmeta_image(0);
        let size = image.len() as u64;
        let (lz4, lz4_size, header) = lz4_mapping(&image);
        let mut infos = vec![
            FirmwareInfo::Normal(FirmwareFile {
                pit_entry: find_entry(&pit_data, "VBMETA_A"),
                file: anon_mapping(&image),
                size,
            }),
            FirmwareInfo::Lz4(FirmwareLz4File {
                pit_entry: find_entry(&pit_data, "VBMETA_B"),
                file: lz4,
                size: lz4_size,
                header,
            }),
            FirmwareInfo::Normal(FirmwareFile {
                pit_entry: find_entry(&pit_data, "VBMETA_SYSTEM_A"),
                file: anon_mapping(&image),
                size,
            }),
            FirmwareInfo::Normal(FirmwareFile {
                pit_entry: find_entry(&pit_data, "BOOT_A"),
                file: anon_mapping(&image),
                size,
            }),
        ];

        rewrite_vbmeta(&pit_data, &mut infos, true, false).unwrap();
        assert_eq!(vbmeta_flags(&normal_bytes(&infos[0]), 0), 0x1);
        assert_eq!(vbmeta_flags(&normal_bytes(&infos[1]), 0), 0x1);

        // Rewriting again accumulates flags, and LZ4 passthrough stays disabled
        rewrite_vbmeta(&pit_data, &mut infos, false, true).unwrap();
        for info in &infos[..2] {
            let data = normal_bytes(info);
            assert_eq!(data.len(), image.len());
            assert_eq!(vbmeta_flags(&data, 0), 0x3);
        }

        // Like fastboot, only top-level vbmeta partitions are rewritten
        assert_eq!(normal_bytes(&infos[2]), image);
        assert_eq!(normal_bytes(&infos[3]), image);
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_disabled_keeps_payloads() {
        let pit_data = ab_pit_data();
        let (lz4, size, header) = lz4_mapping(&crate::avb::tests::vbmeta_image(0));
        let mut infos = vec![FirmwareInfo::Lz4(FirmwareLz4File {
            pit_entry: find_entry(&pit_data, "VBMETA_A"),
            file: lz4,
            size,
            header,
        })];

        rewrite_vbmeta(&pit_data, &mut infos, false, false).unwrap();
        assert!(matches!(infos[0], FirmwareInfo::Lz4(_)));
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_invalid_vbmeta_fails() {
        let pit_data = ab_pit_data();
        let mut infos = vec![FirmwareInfo::Normal(FirmwareFile {
            pit_entry: find_entry(&pit_data, "VBMETA_A"),
            file: anon_mapping(&[0u8; 4096]),
            size: 4096,
        })];

        assert!(matches!(
            rewrite_vbmeta(&pit_data, &mut infos, true, true),
            Err(FlashError::VbmetaRewriteFailed(name, _)) if name == "VBMETA_A"
        ));
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_boot_without_vbmeta_partition() {
        use crate::avb::tests::vbmeta_flags;

        // M3_EUR_OPEN_4G.pit has no vbmeta partition, so the vbmeta in boot's footer
        // is rewritten. A boot image without an AVB footer is rejected.
        let pit_data = PitData::new(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/M3_EUR_OPEN_4G.pit"
        )))
        .unwrap();

        let mut boot = vec![0u8; 16 * 1024];
        boot[0x1000..0x1004].copy_from_slice(b"AVB0");
        let footer = boot.len() - 64;
        boot[footer..footer + 4].copy_from_slice(b"AVBf");
        boot[footer + 20..footer + 28].copy_from_slice(&0x1000u64.to_be_bytes());

        let mut infos = vec![FirmwareInfo::Normal(FirmwareFile {
            pit_entry: find_entry(&pit_data, "BOOT"),
            file: anon_mapping(&boot),
            size: boot.len() as u64,
        })];
        rewrite_vbmeta(&pit_data, &mut infos, true, true).unwrap();
        assert_eq!(vbmeta_flags(&normal_bytes(&infos[0]), 0x1000), 0x3);

        let mut infos = vec![FirmwareInfo::Normal(FirmwareFile {
            pit_entry: find_entry(&pit_data, "BOOT"),
            file: anon_mapping(&[0u8; 4096]),
            size: 4096,
        })];
        assert!(matches!(
            rewrite_vbmeta(&pit_data, &mut infos, true, false),
            Err(FlashError::VbmetaRewriteFailed(_, _))
        ));
    }

    #[test]
    fn test_execute_disable_verity_with_lz4_vbmeta() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir().join("samloader_test_disable_verity");
        let _ = std::fs::create_dir_all(&temp_dir);

        let write_package = |name: &str, vbmeta: &[u8]| {
            let mut encoder = lz4_flex::frame::FrameEncoder::with_frame_info(
                lz4_flex::frame::FrameInfo::new()
                    .content_size(Some(vbmeta.len() as u64))
                    .block_size(lz4_flex::frame::BlockSize::Max1MB)
                    .block_mode(lz4_flex::frame::BlockMode::Independent),
                Vec::new(),
            );
            encoder.write_all(vbmeta).unwrap();
            let vbmeta_lz4 = encoder.finish().unwrap();

            let tar_path = temp_dir.join(name);
            let mut builder = tar::Builder::new(File::create(&tar_path).unwrap());
            let files: [(&str, &[u8]); 2] = [
                ("vbmeta.img.lz4", &vbmeta_lz4),
                ("boot.img", b"DUMMY BOOT IMAGE DATA"),
            ];
            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, content).unwrap();
            }
            builder.finish().unwrap();
            tar_path
        };
        let valid = write_package("valid.tar", &crate::avb::tests::vbmeta_image(0));
        let invalid = write_package("invalid.tar", &[0u8; 4096]);

        let run = |tar_path: &Path, verity: bool| {
            pollster::block_on(async {
                let backend = Box::new(MockBackend::with_profile(
                    crate::usb::DeviceProfile::sm_f968b(),
                ));
                let mut connection = OdinConnection::new(backend);
                connection.init().await.unwrap();
                let mut session = connection.begin_session().await.unwrap();
                assert!(session.is_lz4_supported());
                FlashManager::new(&mut session)
                    .packages(&[tar_path.to_string_lossy()])
                    .disable_verity(verity)
                    .execute()
                    .await
            })
        };

        assert!(run(&valid, false).is_ok());
        assert!(run(&valid, true).is_ok());
        // The vbmeta in the package is only parsed when a rewrite is requested
        assert!(run(&invalid, false).is_ok());
        assert!(matches!(
            run(&invalid, true),
            Err(FlashError::VbmetaRewriteFailed(name, _)) if name == "VBMETA_A"
        ));

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
