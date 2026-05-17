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
use crate::PartitionArg;
use libpit::{PitData, PitEntry};
use std::fs::File;
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;

pub(crate) struct PartitionFlashInfo<'a> {
    pub(crate) pit_entry: &'a PitEntry,
    pub(crate) file: File,
    pub(crate) file_size: u64,
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

    let Some(pit_data) = get_pit_data(&bridge_manager, pit_file.as_ref(), repartition) else {
        return 1;
    };

    let mut partition_infos = Vec::new();

    for part in partitions {
        let entry = if let Ok(id) = part.name.parse::<u32>() {
            pit_data.find_entry_by_id(id)
        } else {
            pit_data.find_entry_by_name(&part.name)
        };

        let Some(entry) = entry else {
            print_error!(
                "Partition \"{}\" does not exist in the specified PIT.",
                part.name
            );
            return 1;
        };

        let Ok((file, file_size)) = File::open(&part.filename).and_then(|f| {
            let file_size = f.metadata()?.len();
            Ok((f, file_size))
        }) else {
            print_error!("Failed to open file \"{}\"", part.filename);
            return 1;
        };

        // Size check
        if !skip_size_check {
            let partition_size = entry.partition_size();
            if partition_size > 0 && file_size > partition_size {
                print_error!(
                    "{} partition is too small for given file. Use --skip-size-check to flash anyways.",
                    part.name
                );
                return 1;
            }
        }

        partition_infos.push(PartitionFlashInfo {
            pit_entry: entry,
            file,
            file_size,
        });
    }

    if let Err(e) = send_total_transfer_size(
        &bridge_manager,
        &partition_infos,
        pit_file.as_ref(),
        repartition,
    ) {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = flash_partitions(&bridge_manager, partition_infos, &pit_data, repartition) {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = bridge_manager.end_session() {
        print_error!("{}", e);
        return 1;
    }

    0
}

fn send_total_transfer_size(
    bridge_manager: &BridgeManager,
    partition_files: &[PartitionFlashInfo],
    pit_file: Option<&File>,
    repartition: bool,
) -> Result<(), String> {
    let mut total_bytes: u64 = 0;

    for part in partition_files {
        total_bytes += part.file_size;
    }

    if repartition {
        if let Some(f) = pit_file {
            let pit_size = f.metadata().map_err(|e| e.to_string())?.len();
            total_bytes += pit_size;
        }
    }

    bridge_manager.set_total_bytes(total_bytes)?;

    Ok(())
}

fn get_pit_data(
    bridge_manager: &BridgeManager,
    pit_file: Option<&File>,
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
            Ok(pit_buffer) => match PitData::new(&pit_buffer) {
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
            },
            Err(e) => {
                print_error!("{}", e);
                None
            }
        }
    }
}

fn flash_partitions(
    bridge_manager: &BridgeManager,
    partition_files: Vec<PartitionFlashInfo>,
    pit_data: &PitData,
    repartition: bool,
) -> Result<(), String> {
    if repartition {
        println!("Uploading PIT");
        bridge_manager.send_pit_data(pit_data)?;
        println!("PIT upload successful\n");
    }

    for info in partition_files {
        println!("Uploading {}", info.pit_entry.partition_name);
        bridge_manager.send_file(&info)?;
        println!("{} upload successful\n", info.pit_entry.partition_name);
    }

    Ok(())
}
