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

use crate::PartitionArg;
use crate::print_error;
use indicatif::{ProgressBar, ProgressStyle};
use samloader_odin::{
    FlashEvent, FlashManager, FlashProgress, OdinConnection, RebootMode, UsbBackendOption,
    create_backend, set_progress,
};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "{msg}\n[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

pub(crate) struct CliProgress {
    progress_bar: std::sync::Mutex<Option<ProgressBar>>,
    verbose: bool,
}

impl CliProgress {
    pub(crate) fn new(verbose: bool) -> Self {
        Self {
            progress_bar: std::sync::Mutex::new(None),
            verbose,
        }
    }
}

impl FlashProgress for CliProgress {
    fn set_length(&self, len: u64) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.set_length(len);
        }
    }

    fn inc(&self, bytes: u64) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.inc(bytes);
        }
    }

    fn println(&self, msg: &str) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.println(msg);
        } else {
            println!("{}", msg);
        }
    }

    fn println_verbose(&self, msg: &str) {
        if self.verbose {
            self.println(msg);
        }
    }

    fn on_event(&self, event: FlashEvent<'_>) {
        match event {
            FlashEvent::PartitionStart { name, size } => {
                let pb = ProgressBar::no_length()
                    .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
                pb.enable_steady_tick(Duration::from_secs(1));
                pb.set_message(format!("Flashing {}", name));
                if size > 0 {
                    pb.set_length(size);
                }
                *self.progress_bar.lock().unwrap() = Some(pb);
            }
            FlashEvent::PartitionEnd(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.set_message(format!("{} flash successful", name));
                    pb.finish();
                    println!();
                }
            }
            FlashEvent::PartitionFail(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.abandon_with_message(format!("{} flash failed", name));
                }
            }
            FlashEvent::Md5Start {
                name,
                size: total_bytes,
            } => {
                let pb = ProgressBar::no_length()
                    .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
                pb.enable_steady_tick(Duration::from_secs(1));
                pb.set_message(format!("Verifying MD5 checksum for {}", name));
                if total_bytes > 0 {
                    pb.set_length(total_bytes);
                }
                *self.progress_bar.lock().unwrap() = Some(pb);
            }
            FlashEvent::Md5End(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.set_message(format!("{} MD5 verification successful", name));
                    pb.finish();
                    println!();
                }
            }
            FlashEvent::Md5Fail(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.abandon_with_message(format!("{} MD5 verification failed", name));
                }
            }
        }
    }
}

// Strips any directory and .lz4 suffix, like the partition matching done when flashing
fn normalize_basename(path: &str) -> String {
    let name = Path::new(path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name.len().checked_sub(4) {
        Some(stem) if name[stem..].eq_ignore_ascii_case(".lz4") => name[..stem].to_string(),
        _ => name,
    }
}

// Lists the file names that will be flashed from packages, honoring download-list.txt
fn package_flash_names(packages: &[String]) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut download_list: Option<HashSet<String>> = None;
    for pkg in packages {
        let mut archive = tar::Archive::new(File::open(pkg)?);
        for entry in archive.entries_with_seek()? {
            let mut entry = entry?;
            let name = normalize_basename(&entry.path()?.to_string_lossy());
            if name == "download-list.txt" {
                let mut content = String::new();
                entry.read_to_string(&mut content)?;
                download_list = Some(content.lines().map(|s| s.trim().to_string()).collect());
            } else {
                names.push(name);
            }
        }
    }
    if let Some(list) = download_list {
        names.retain(|name| list.contains(name));
    }
    Ok(names)
}

// Checks whether userdata is flashed before talking to the device, so without its PIT.
// Packages and auto-matched files are checked by file name, and explicit partitions by
// partition name. Partitions given by numeric ID cannot be resolved and are not checked.
fn flashes_userdata(
    packages: &[String],
    partitions: &[PartitionArg],
    skip: &[String],
) -> io::Result<bool> {
    let is_skipped = |name: &str| {
        skip.iter().any(|target| {
            let target = target.trim();
            target.eq_ignore_ascii_case("USERDATA")
                || normalize_basename(target).eq_ignore_ascii_case(name)
        })
    };

    let mut names = package_flash_names(packages)?;
    for part in partitions {
        names.push(match &part.name {
            Some(name) => name.clone(),
            None => normalize_basename(&part.filename),
        });
    }
    Ok(names
        .iter()
        .any(|name| name.to_ascii_lowercase().starts_with("userdata") && !is_skipped(name)))
}

// Asks a y/n question on the terminal, declining when stdin is closed
fn confirm(question: &str) -> bool {
    let mut stdin = io::stdin().lock();
    loop {
        print!("{} [y/n] ", question);
        let _ = io::stdout().flush();

        let mut answer = String::new();
        if stdin.read_line(&mut answer).unwrap_or(0) == 0 {
            println!();
            return false;
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn action_flash(
    usb_backend: UsbBackendOption,
    verbose: bool,
    reboot_mode: RebootMode,
    wait: bool,
    skip_size_check: bool,
    skip_md5: bool,
    pit: Option<&str>,
    packages: &[String],
    partitions: &[PartitionArg],
    skip: &[String],
    disable_verity: bool,
    disable_verification: bool,
    csc_code: Option<&str>,
    erase: bool,
    force: bool,
) -> i32 {
    if !force {
        match flashes_userdata(packages, partitions, skip) {
            Ok(false) => {}
            Ok(true) => {
                if !confirm(
                    "Flash list contains userdata. This will wipe the device's data. Continue?",
                ) {
                    print_error!("Flashing aborted by user.");
                    return 1;
                }
            }
            Err(e) => {
                print_error!("Failed to read packages: {}", e);
                return 1;
            }
        }
    }

    set_progress(CliProgress::new(verbose));

    pollster::block_on(async {
        let usb = match create_backend(usb_backend, wait).await {
            Ok(u) => u,
            Err(e) => {
                print_error!("{}", e);
                return 1;
            }
        };
        let mut connection = OdinConnection::new(usb);

        if let Err(e) = connection.init().await {
            print_error!("{}", e);
            return 1;
        }

        let mut session = match connection.begin_session().await {
            Ok(s) => s,
            Err(e) => {
                print_error!("{}", e);
                return 1;
            }
        };

        let mapped_partitions: Vec<(Option<String>, String)> = partitions
            .iter()
            .map(|p| (p.name.clone(), p.filename.clone()))
            .collect();

        let mut flash_manager = FlashManager::new(&mut session)
            .reboot_mode(reboot_mode)
            .skip_size_check(skip_size_check)
            .skip_md5(skip_md5)
            .erase(erase)
            .packages(packages)
            .partitions(&mapped_partitions)
            .skip(skip)
            .disable_verity(disable_verity)
            .disable_verification(disable_verification)
            .sales_code(csc_code);

        if let Some(pit_path) = pit {
            flash_manager = flash_manager.pit(pit_path);
        }

        if let Err(e) = flash_manager.execute().await {
            print_error!("{}", e);
            return 1;
        }

        0
    })
}
