// Copyright 2026 Google LLC
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

use crate::bridge_manager::BridgeManager;
use crate::print_error;
use crate::version;
use crate::FileTransferDestination;
use crate::PartitionArg;
use libpit::{BinaryType, DeviceType, PitData, PitEntry};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::thread::sleep;
use std::time::Duration;

struct PartitionFile {
    argument_name: String,
    file: File,
    file_size: u32,
}

struct PartitionFlashInfo<'a> {
    pit_entry: &'a PitEntry,
    file: File,
    file_size: u32,
}

pub(crate) fn action_flash(
    repartition: bool,
    verbose: bool,
    wait: bool,
    usb_log_level: &str,
    skip_size_check: bool,
    pit: &str,
    partitions: &[PartitionArg],
) -> i32 {
    if repartition && pit.is_empty() {
        println!("If you wish to repartition then a PIT file must be specified.\n");
        return 0;
    }

    // Open files
    let mut pit_file = None;
    if !pit.is_empty() {
        match File::open(pit) {
            Ok(f) => pit_file = Some(f),
            Err(_) => {
                print_error!("Failed to open file \"{}\"", pit);
                return 1;
            }
        }
    }

    let partition_files: Vec<PartitionFile> = match partitions
        .iter()
        .map(|part| {
            File::open(&part.filename)
                .map_err(|_| part.filename.clone())
                .and_then(|mut f| {
                    let file_size = f.seek(SeekFrom::End(0)).map_err(|_| part.filename.clone())? as u32;
                    f.seek(SeekFrom::Start(0)).map_err(|_| part.filename.clone())?;
                    Ok(PartitionFile {
                        argument_name: part.name.clone(),
                        file: f,
                        file_size,
                    })
                })
        })
        .collect::<Result<Vec<_>, String>>()
    {
        Ok(files) => files,
        Err(filename) => {
            print_error!("Failed to open file \"{}\"", filename);
            return 1;
        }
    };

    if partition_files.is_empty() {
        println!("No partitions to flash.");
        return 0;
    }

    // Info
    version::print_release_info();
    sleep(Duration::from_millis(1000));

    // Perform flash
    let mut bridge_manager = BridgeManager::new(verbose, wait);
    bridge_manager.set_usb_log_level(usb_log_level);

    if let Err(e) = bridge_manager.initialise() {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = bridge_manager.begin_session() {
        print_error!("{}", e);
        return 1;
    }

    let mut success = true;

    if let Err(e) = send_total_transfer_size(
        &bridge_manager,
        &partition_files,
        pit_file.as_ref(),
        repartition,
    ) {
        print_error!("{}", e);
        success = false;
    }

    if success {
        if let Some(pit_data) = get_pit_data(&bridge_manager, pit_file, repartition) {
            if let Err(e) = flash_partitions(
                &bridge_manager,
                partition_files,
                &pit_data,
                repartition,
                skip_size_check,
            ) {
                print_error!("{}", e);
                success = false;
            }
        } else {
            success = false;
        }
    }

    if let Err(e) = bridge_manager.end_session() {
        print_error!("{}", e);
        success = false;
    }

    if success {
        0
    } else {
        1
    }
}

fn send_total_transfer_size(
    bridge_manager: &BridgeManager,
    partition_files: &[PartitionFile],
    pit_file: Option<&File>,
    repartition: bool,
) -> Result<(), String> {
    let mut total_bytes: u64 = 0;

    for part in partition_files {
        total_bytes += part.file_size as u64;
    }

    if repartition {
        if let Some(f) = pit_file {
            let pit_size = f.metadata().map_err(|e| e.to_string())?.len();
            total_bytes += pit_size;
        }
    }

    bridge_manager.send_total_bytes(total_bytes)?;

    let mut total_bytes_result = 0;
    bridge_manager.receive_session_setup_response(&mut total_bytes_result)?;

    if total_bytes_result != 0 {
        return Err(format!(
            "Unexpected session total bytes response!\nExpected: 0\nReceived:{}",
            total_bytes_result
        ));
    }

    Ok(())
}

fn get_pit_data(
    bridge_manager: &BridgeManager,
    pit_file: Option<File>,
    repartition: bool,
) -> Option<PitData> {
    let mut local_pit_data = None;

    if let Some(mut f) = pit_file {
        let mut buffer = Vec::new();
        if f.read_to_end(&mut buffer).is_ok() {
            match PitData::new(&buffer) {
                Ok(data) => local_pit_data = Some(data),
                Err(_) => {
                    print_error!("Failed to unpack PIT file!");
                    return None;
                }
            }
        } else {
            print_error!("Failed to read PIT file.");
            return None;
        }
    }

    if repartition {
        local_pit_data
    } else {
        match bridge_manager.download_pit_file() {
            Ok(pit_buffer) => {
                match PitData::new(&pit_buffer) {
                    Ok(device_pit_data) => {
                        if let Some(local_pit) = local_pit_data {
                            if device_pit_data != local_pit {
                                println!("Local and device PIT files don't match and repartition wasn't specified!");
                                print_error!("Flash aborted!");
                                return None;
                            }
                        }
                        Some(device_pit_data)
                    }
                    Err(_) => {
                        print_error!("Failed to unpack device's PIT file!");
                        None
                    }
                }
            }
            Err(e) => {
                print_error!("{}", e);
                None
            }
        }
    }
}

fn flash_partitions(
    bridge_manager: &BridgeManager,
    partition_files: Vec<PartitionFile>,
    pit_data: &PitData,
    repartition: bool,
    skip_size_check: bool,
) -> Result<(), String> {
    let mut partition_flash_infos = Vec::new();

    for part_file in partition_files {
        let entry = if let Ok(id) = part_file.argument_name.parse::<u32>() {
            pit_data.find_entry_by_id(id)
        } else {
            let mut name = part_file.argument_name.clone();
            if name == "PIT" {
                name = "pit".to_string();
            }
            pit_data.find_entry_by_name(&name)
        };

        match entry {
            Some(e) => {
                // Size check
                if !skip_size_check {
                    let device_type = e.device_type;
                    if device_type == DeviceType::MMC || device_type == DeviceType::UFS {
                        // MMC or UFS
                        let partition_size = e.block_count as u64;
                        let block_size = if device_type == DeviceType::UFS { 4096 } else { 512 };
                        if partition_size > 0
                            && (part_file.file_size as u64) > partition_size * block_size
                        {
                            return Err(format!(
                                "{} partition is too small for given file. Use --skip-size-check to flash anyways.",
                                part_file.argument_name
                            ));
                        }
                    }
                }

                partition_flash_infos.push(PartitionFlashInfo {
                    pit_entry: e,
                    file: part_file.file,
                    file_size: part_file.file_size,
                });
            }
            None => {
                return Err(format!(
                    "Partition \"{}\" does not exist in the specified PIT.",
                    part_file.argument_name
                ));
            }
        }
    }

    if repartition {
        println!("Uploading PIT");
        bridge_manager.send_pit_data(pit_data)?;
        println!("PIT upload successful\n");
    }

    for mut info in partition_flash_infos {
        println!("Uploading {}", info.pit_entry.partition_name);

        let destination = if info.pit_entry.binary_type == BinaryType::CommunicationProcessor {
            FileTransferDestination::Modem
        } else {
            FileTransferDestination::Phone
        };

        let identifier = if destination == FileTransferDestination::Modem {
            0xFFFFFFFF
        } else {
            info.pit_entry.identifier
        };

        bridge_manager.send_file_from_reader(
            &mut info.file,
            info.file_size,
            destination,
            info.pit_entry.device_type,
            identifier,
        )?;
        println!("{} upload successful\n", info.pit_entry.partition_name);
    }

    Ok(())
}
