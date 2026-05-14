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

use crate::packets;
use crate::{print_error, print_warning};
use libpit::{BinaryType, PitData, PitEntry};
use rusb::{Context, DeviceHandle, LogLevel, UsbContext};
use std::time::Duration;

#[derive(Copy, Clone, PartialEq, Eq)]
enum EmptyTransferMode {
    None = 0x0,
    Before = 0x1,
    After = 0x2,
    BeforeAndAfter = 0x3,
}

pub(crate) struct BridgeManager {
    verbose: bool,
    wait_for_device: bool,
    context: Context,
    handle: Option<DeviceHandle<Context>>,
    usb_log_level: LogLevel,

    interface_index: i32,
    alt_setting_index: i32,
    in_endpoint: u8,
    out_endpoint: u8,

    interface_claimed: bool,

    file_transfer_sequence_max_length: u32,
    file_transfer_packet_size: u32,
    file_transfer_sequence_timeout: u32,
}

const VID_SAMSUNG: u16 = 0x04E8;
const PID_GALAXY_S: u16 = 0x6601;
const PID_GALAXY_S2: u16 = 0x685D;
const PID_DROID_CHARGE: u16 = 0x68C3;

const SUPPORTED_DEVICES: &[(u16, u16)] = &[
    (VID_SAMSUNG, PID_GALAXY_S),
    (VID_SAMSUNG, PID_GALAXY_S2),
    (VID_SAMSUNG, PID_DROID_CHARGE),
];

const FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT: u32 = 800;
const FILE_TRANSFER_PACKET_SIZE_DEFAULT: u32 = 131072;
const FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT: u32 = 30000;

const USB_CLASS_CDC_DATA: u8 = 0x0A;

impl BridgeManager {
    pub(crate) fn new(verbose: bool, wait_for_device: bool) -> Self {
        let context = Context::new().expect("Failed to create libusb context");
        Self {
            verbose,
            wait_for_device,
            context,
            handle: None,
            usb_log_level: LogLevel::Error,

            interface_index: -1,
            alt_setting_index: -1,
            in_endpoint: 0,
            out_endpoint: 0,

            interface_claimed: false,

            file_transfer_sequence_max_length: FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT,
            file_transfer_packet_size: FILE_TRANSFER_PACKET_SIZE_DEFAULT,
            file_transfer_sequence_timeout: FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT,
        }
    }

    pub(crate) fn set_usb_log_level(&mut self, level: &str) {
        self.usb_log_level = match level.to_lowercase().as_str() {
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warning" => LogLevel::Warning,
            "error" => LogLevel::Error,
            "none" => LogLevel::None,
            _ => LogLevel::Error,
        };
        self.context.set_log_level(self.usb_log_level);
    }

    pub(crate) fn detect_device(&mut self) -> Result<(), String> {
        if self.wait_for_device {
            println!("Waiting for device...");
        }

        loop {
            if let Ok(devices) = self.context.devices() {
                for device in devices.iter() {
                    if let Ok(descriptor) = device.device_descriptor() {
                        for &(vid, pid) in SUPPORTED_DEVICES {
                            if descriptor.vendor_id() == vid && descriptor.product_id() == pid {
                                println!("Device detected");
                                return Ok(());
                            }
                        }
                    }
                }
            }

            if self.wait_for_device {
                std::thread::sleep(Duration::from_secs(1));
            } else {
                break;
            }
        }

        Err("Failed to detect compatible download-mode device.".to_string())
    }

    fn find_device_interface(&mut self) -> Result<(), String> {
        if self.wait_for_device {
            println!("Waiting for device...");
        } else {
            println!("Detecting device...");
        }

        let mut heimdall_device = None;

        loop {
            if let Ok(devices) = self.context.devices() {
                for device in devices.iter() {
                    if let Ok(descriptor) = device.device_descriptor() {
                        for &(vid, pid) in SUPPORTED_DEVICES {
                            if descriptor.vendor_id() == vid && descriptor.product_id() == pid {
                                heimdall_device = Some(device);
                                break;
                            }
                        }
                    }
                    if heimdall_device.is_some() {
                        break;
                    }
                }
            }

            if heimdall_device.is_some() {
                break;
            }

            if self.wait_for_device {
                std::thread::sleep(Duration::from_secs(1));
            } else {
                break;
            }
        }

        let device = match heimdall_device {
            Some(d) => d,
            None => return Err("Failed to detect compatible download-mode device.".to_string()),
        };

        let handle = match device.open() {
            Ok(h) => h,
            Err(e) => return Err(format!("Failed to access device. libusb error: {}", e)),
        };

        if let Ok(config) = handle.active_configuration() {
            if config != 1 {
                let _ = handle.set_active_configuration(1);
            }
        } else {
            let _ = handle.set_active_configuration(1);
        }

        if self.verbose {
            if let Ok(descriptor) = device.device_descriptor() {
                if let Ok(languages) = handle.read_languages(Duration::from_secs(1)) {
                    if !languages.is_empty() {
                        if let Ok(manufacturer) = handle.read_manufacturer_string_ascii(&descriptor)
                        {
                            println!("      Manufacturer: \"{}\"", manufacturer);
                        }
                        if let Ok(product) = handle.read_product_string_ascii(&descriptor) {
                            println!("           Product: \"{}\"", product);
                        }
                        if let Ok(serial) = handle.read_serial_number_string_ascii(&descriptor) {
                            println!("         Serial No: \"{}\"", serial);
                        }
                    }
                }

                println!("\n            length: {}", descriptor.length());
                println!("      device class: {}", descriptor.class_code());
                println!(
                    "               S/N: {}",
                    descriptor.serial_number_string_index().unwrap_or(0)
                );
                println!(
                    "           VID:PID: {:04X}:{:04X}",
                    descriptor.vendor_id(),
                    descriptor.product_id()
                );

                let version = descriptor.device_version();
                let bcd = (version.0 as u16) << 8 | (version.1 as u16) << 4 | (version.2 as u16);
                println!("         bcdDevice: {:04X}", bcd);

                println!(
                    "   iMan:iProd:iSer: {}:{}:{}",
                    descriptor.manufacturer_string_index().unwrap_or(0),
                    descriptor.product_string_index().unwrap_or(0),
                    descriptor.serial_number_string_index().unwrap_or(0)
                );
                println!("          nb confs: {}", descriptor.num_configurations());
            }
        }

        let config_descriptor = device
            .config_descriptor(0)
            .map_err(|_| "Failed to retrieve config descriptor".to_string())?;

        self.interface_index = -1;
        self.alt_setting_index = -1;

        for interface in config_descriptor.interfaces() {
            for setting in interface.descriptors() {
                if self.verbose {
                    println!(
                        "\ninterface[{}].altsetting[{}]: num endpoints = {}",
                        interface.number(),
                        setting.setting_number(),
                        setting.num_endpoints()
                    );
                    println!(
                        "   Class.SubClass.Protocol: {:02X}.{:02X}.{:02X}",
                        setting.class_code(),
                        setting.sub_class_code(),
                        setting.protocol_code()
                    );
                }

                let mut in_endpoint_address = None;
                let mut out_endpoint_address = None;

                for (i, endpoint) in setting.endpoint_descriptors().enumerate() {
                    if self.verbose {
                        println!("       endpoint[{}].address: {:02X}", i, endpoint.address());
                        println!(
                            "           max packet size: {:04X}",
                            endpoint.max_packet_size()
                        );
                        println!("          polling interval: {:02X}", endpoint.interval());
                    }

                    if endpoint.direction() == rusb::Direction::In {
                        in_endpoint_address = Some(endpoint.address());
                    } else {
                        out_endpoint_address = Some(endpoint.address());
                    }
                }

                if self.interface_index < 0
                    && setting.num_endpoints() == 2
                    && setting.class_code() == USB_CLASS_CDC_DATA
                {
                    if let (Some(in_addr), Some(out_addr)) =
                        (in_endpoint_address, out_endpoint_address)
                    {
                        self.interface_index = interface.number() as i32;
                        self.alt_setting_index = setting.setting_number() as i32;
                        self.in_endpoint = in_addr;
                        self.out_endpoint = out_addr;
                    }
                }
            }
        }

        if self.interface_index < 0 {
            return Err("Failed to find correct interface configuration".to_string());
        }

        self.handle = Some(handle);
        Ok(())
    }

    fn claim_device_interface(&mut self) -> Result<(), String> {
        println!("Claiming interface...");

        let handle = self.handle.as_mut().unwrap();
        if handle.claim_interface(self.interface_index as u8).is_err() {
            #[cfg(target_os = "linux")]
            {
                println!("Attempt failed. Detaching driver...");
                let _ = handle.detach_kernel_driver(self.interface_index as u8);
                println!("Claiming interface again...");
                if handle.claim_interface(self.interface_index as u8).is_err() {
                    return Err("Claiming interface failed!".to_string());
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err("Claiming interface failed!".to_string());
            }
        }

        self.interface_claimed = true;
        Ok(())
    }

    fn setup_device_interface(&mut self) -> Result<(), String> {
        if self.alt_setting_index == 0 {
            return Ok(());
        }

        println!("Setting up interface...");

        let handle = self.handle.as_mut().unwrap();
        handle
            .set_alternate_setting(self.interface_index as u8, self.alt_setting_index as u8)
            .map_err(|_| "Setting up interface failed!".to_string())?;

        println!();
        Ok(())
    }

    fn release_device_interface(&mut self) {
        println!("Releasing device interface...");

        if let Some(handle) = self.handle.as_mut() {
            let _ = handle.release_interface(self.interface_index as u8);

            #[cfg(target_os = "linux")]
            {
                let _ = handle.attach_kernel_driver(self.interface_index as u8);
            }
        }

        self.interface_claimed = false;
        println!();
    }

    fn initialise_protocol(&mut self) -> Result<(), String> {
        println!("Initialising protocol...");

        {
            let handle = self.handle.as_mut().unwrap();
            println!("Resetting device...");
            if let Err(e) = handle.reset() {
                print_warning!("Failed to reset device! Result: {}", e);
            }
        }

        self.send_bulk_transfer(b"ODIN", 1000, true)
            .then_some(())
            .ok_or_else(|| "Failed to send handshake!".to_string())?;

        let mut data_buffer = [0u8; 1024];
        let data_transferred = self.receive_bulk_transfer(&mut data_buffer, 1000, true);

        if data_transferred == 4 && &data_buffer[0..4] == b"LOKE" {
            println!("Protocol initialisation successful.\n");
            Ok(())
        } else {
            if self.verbose {
                if data_transferred >= 0 {
                    return Err(format!(
                        "Unexpected handshake response!\nExpected: \"LOKE\"\nReceived: \"{}\"",
                        String::from_utf8_lossy(&data_buffer[0..data_transferred as usize])
                    ));
                } else {
                    return Err(
                        "Unexpected handshake response!\nFailed to receive handshake response."
                            .to_string(),
                    );
                }
            }
            Err("Unexpected handshake response!".to_string())
        }
    }

    pub(crate) fn initialise(&mut self) -> Result<(), String> {
        println!("Initialising connection...");

        self.find_device_interface()?;
        self.claim_device_interface()?;
        self.setup_device_interface()?;
        self.initialise_protocol()?;

        Ok(())
    }

    pub(crate) fn begin_session(&mut self) -> Result<(), String> {
        println!("Beginning session...");

        let packet = packets::OutboundPacket::begin_session();
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to begin session!".to_string())?;

        let response = self.receive_packet(3000, EmptyTransferMode::None)?;

        if response.response_type != packets::RESPONSE_TYPE_SESSION_SETUP {
            return Err("Failed to unpack session setup response!".to_string());
        }
        let device_default_packet_size = response.value;

        println!("\nSome devices may take up to 2 minutes to respond.\nPlease be patient!\n");
        std::thread::sleep(Duration::from_millis(3000));

        if device_default_packet_size != 0 {
            self.file_transfer_sequence_timeout = 120000;
            self.file_transfer_packet_size = 1048576;
            self.file_transfer_sequence_max_length = 30;

            let packet = packets::OutboundPacket::file_part_size(self.file_transfer_packet_size);
            self.send_packet(&packet, 3000, EmptyTransferMode::After)
                .map_err(|_| "Failed to send file part size packet!".to_string())?;

            let response = self.receive_packet(3000, EmptyTransferMode::None)?;

            if response.response_type != packets::RESPONSE_TYPE_SESSION_SETUP {
                return Err("Failed to unpack file part size response!".to_string());
            }
            if response.value != 0 {
                return Err(format!(
                    "Unexpected file part size response!\nExpected: 0\nReceived: {}",
                    response.value
                ));
            }
        }

        println!("Session begun.\n");
        Ok(())
    }

    pub(crate) fn end_session(&self) -> Result<(), String> {
        println!("Ending session...");

        let packet = packets::OutboundPacket::end_session(0); // kRequestEndSession
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to send end session packet!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to receive session end confirmation!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_END_SESSION {
            return Err("Failed to receive session end confirmation!".to_string());
        }

        println!("Rebooting device...");

        let packet = packets::OutboundPacket::end_session(1); // kRequestRebootDevice
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to send reboot device packet!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to receive reboot confirmation!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_END_SESSION {
            return Err("Failed to receive reboot confirmation!".to_string());
        }

        Ok(())
    }

    fn send_bulk_transfer(&self, data: &[u8], timeout: i32, retry: bool) -> bool {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return false,
        };

        let mut result = handle.write_bulk(
            self.out_endpoint,
            data,
            Duration::from_millis(timeout as u64),
        );

        if result.is_err() && retry {
            let retry_delay = 250;
            if self.verbose {
                print_warning!(
                    "libusb error {} whilst sending bulk transfer.",
                    result.as_ref().unwrap_err()
                );
            }

            for i in 0..5 {
                if self.verbose {
                    println!(" Retrying...");
                }
                std::thread::sleep(Duration::from_millis(retry_delay * (i + 1)));
                result = handle.write_bulk(
                    self.out_endpoint,
                    data,
                    Duration::from_millis(timeout as u64),
                );
                if result.is_ok() {
                    break;
                }
                if self.verbose {
                    print_warning!(
                        "libusb error {} whilst sending bulk transfer.",
                        result.as_ref().unwrap_err()
                    );
                }
            }
            if self.verbose {
                println!();
            }
        }

        match result {
            Ok(transferred) => transferred == data.len(),
            Err(_) => false,
        }
    }

    fn receive_bulk_transfer(&self, data: &mut [u8], timeout: i32, retry: bool) -> i32 {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return -1,
        };

        let mut result = handle.read_bulk(
            self.in_endpoint,
            data,
            Duration::from_millis(timeout as u64),
        );

        if result.is_err() && retry {
            let retry_delay = 250;
            if self.verbose {
                print_warning!(
                    "libusb error {} whilst receiving bulk transfer.",
                    result.as_ref().unwrap_err()
                );
            }

            for i in 0..5 {
                if self.verbose {
                    println!(" Retrying...");
                }
                std::thread::sleep(Duration::from_millis(retry_delay * (i + 1)));
                result = handle.read_bulk(
                    self.in_endpoint,
                    data,
                    Duration::from_millis(timeout as u64),
                );
                if result.is_ok() {
                    break;
                }
                if self.verbose {
                    print_warning!(
                        "libusb error {} whilst receiving bulk transfer.",
                        result.as_ref().unwrap_err()
                    );
                }
            }
            if self.verbose {
                println!();
            }
        }

        match result {
            Ok(transferred) => transferred as i32,
            Err(_) => -1,
        }
    }

    fn send_raw_packet(
        &self,
        packet: &[u8],
        timeout: i32,
        empty_transfer_mode: EmptyTransferMode,
    ) -> Result<(), ()> {
        if (empty_transfer_mode as u32) & (EmptyTransferMode::Before as u32) != 0
            && !self.send_bulk_transfer(&[], 100, false)
            && self.verbose
        {
            print_warning!(
                "Empty bulk transfer before sending packet failed. Continuing anyway..."
            );
        }

        if !self.send_bulk_transfer(packet, timeout, true) {
            return Err(());
        }

        if (empty_transfer_mode as u32) & (EmptyTransferMode::After as u32) != 0
            && !self.send_bulk_transfer(&[], 100, false)
            && self.verbose
        {
            print_warning!("Empty bulk transfer after sending packet failed. Continuing anyway...");
        }

        Ok(())
    }

    fn send_packet(
        &self,
        packet: &packets::OutboundPacket,
        timeout: i32,
        empty_transfer_mode: EmptyTransferMode,
    ) -> Result<(), ()> {
        let packet_bytes = packet.pack();
        self.send_raw_packet(&packet_bytes, timeout, empty_transfer_mode)
    }

    fn receive_raw_packet(
        &self,
        packet: &mut [u8],
        timeout: i32,
        empty_transfer_mode: EmptyTransferMode,
    ) -> Result<(), String> {
        if (empty_transfer_mode as u32) & (EmptyTransferMode::Before as u32) != 0
            && self.receive_bulk_transfer(&mut [], 100, false) < 0
            && self.verbose
        {
            print_warning!(
                "Empty bulk transfer before receiving packet failed. Continuing anyway..."
            );
        }

        let received_size = self.receive_bulk_transfer(packet, timeout, true);

        if received_size < 0 {
            return Err("Failed to receive packet!".to_string());
        }

        if received_size as usize != packet.len() {
            return Err(format!(
                "Incorrect packet size received - expected size = {}, received size = {}.",
                packet.len(),
                received_size
            ));
        }

        if (empty_transfer_mode as u32) & (EmptyTransferMode::After as u32) != 0
            && self.receive_bulk_transfer(&mut [], 100, false) < 0
            && self.verbose
        {
            print_warning!(
                "Empty bulk transfer after receiving packet failed. Continuing anyway..."
            );
        }

        Ok(())
    }

    fn receive_packet(
        &self,
        timeout: i32,
        empty_transfer_mode: EmptyTransferMode,
    ) -> Result<packets::Response, String> {
        let mut buffer = [0u8; 8];
        self.receive_raw_packet(&mut buffer, timeout, empty_transfer_mode)?;

        let mut reader = binrw::io::Cursor::new(&buffer);
        use binrw::BinRead;
        packets::Response::read_le(&mut reader).map_err(|_| "Failed to unpack packet".to_string())
    }

    pub(crate) fn send_pit_data(&self, pit_data: &PitData) -> Result<(), String> {
        let pit_buffer_size = pit_data.get_padded_size();

        // Start file transfer
        let packet = packets::OutboundPacket::pit_file_flash();
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to initialise PIT file transfer!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to confirm transfer initialisation!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_PIT_FILE {
            return Err("Failed to confirm transfer initialisation!".to_string());
        }

        // Transfer file size
        let packet = packets::OutboundPacket::flash_part_pit_file(pit_buffer_size);
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to send PIT file part information!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to confirm sending of PIT file part information!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_PIT_FILE {
            return Err("Failed to confirm sending of PIT file part information!".to_string());
        }

        // Create packed in-memory PIT file
        let mut pit_buffer = vec![0u8; pit_buffer_size as usize];
        pit_data.pack(&mut pit_buffer);

        // Flash pit file
        let packet = packets::create_send_file_part_packet(&pit_buffer, pit_buffer_size);
        self.send_raw_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to send file part packet!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to receive PIT file part response!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_PIT_FILE {
            return Err("Failed to receive PIT file part response!".to_string());
        }

        // End pit file transfer
        let packet = packets::OutboundPacket::end_pit_file_transfer(pit_buffer_size);
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to send end PIT file transfer packet!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to confirm end of PIT file transfer!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_PIT_FILE {
            return Err("Failed to confirm end of PIT file transfer!".to_string());
        }

        Ok(())
    }

    fn receive_pit_file(&self) -> Result<Vec<u8>, String> {
        let packet = packets::OutboundPacket::pit_file_dump();
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to request receival of PIT file!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to receive PIT file size!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_PIT_FILE {
            return Err("Failed to receive PIT file size!".to_string());
        }
        let file_size = response.value;

        let mut transfer_count = file_size / 500; // ReceiveFilePartPacket::kDataSize
        if file_size % 500 != 0 {
            transfer_count += 1;
        }

        let mut buffer = Vec::with_capacity(file_size as usize);

        for i in 0..transfer_count {
            let packet = packets::OutboundPacket::dump_part_pit_file(i);
            self.send_packet(&packet, 3000, EmptyTransferMode::After)
                .map_err(|_| format!("Failed to request PIT file part #{}!", i))?;

            let receive_empty_transfer_mode = if i == transfer_count - 1 {
                EmptyTransferMode::After
            } else {
                EmptyTransferMode::None
            };

            let mut part_buffer = [0u8; 500]; // ReceiveFilePartPacket::kDataSize
            let received_size = self.receive_bulk_transfer(&mut part_buffer, 3000, true);

            if received_size < 0 {
                return Err(format!("Failed to receive PIT file part #{}!", i));
            }

            buffer.extend_from_slice(&part_buffer[0..received_size as usize]);

            if receive_empty_transfer_mode == EmptyTransferMode::After {
                let mut dummy = [0u8; 0];
                let _ = self.receive_bulk_transfer(&mut dummy, 100, false);
            }
        }

        // End file transfer
        let packet = packets::OutboundPacket::pit_file_end();
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to send request to end PIT file transfer!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to receive end PIT file transfer verification!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_PIT_FILE {
            return Err("Failed to receive end PIT file transfer verification!".to_string());
        }

        Ok(buffer)
    }

    pub(crate) fn download_pit_file(&self) -> Result<Vec<u8>, String> {
        println!("Downloading device's PIT file...");

        let pit_file = self.receive_pit_file().map_err(|e| {
            print_error!("{}", e);
            "Failed to download PIT file!".to_string()
        })?;

        println!("PIT file download successful.\n");
        Ok(pit_file)
    }

    pub(crate) fn send_file_from_reader<R: std::io::Read + std::io::Seek>(
        &self,
        reader: &mut R,
        file_size: u32,
        pit_entry: &PitEntry,
    ) -> Result<(), String> {
        // Start file transfer
        let packet = packets::OutboundPacket::file_transfer_flash();
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to initialise file transfer!".to_string())?;

        let response = self
            .receive_packet(3000, EmptyTransferMode::None)
            .map_err(|_| "Failed to confirm transfer initialisation!".to_string())?;

        if response.response_type != packets::RESPONSE_TYPE_FILE_TRANSFER {
            return Err("Failed to confirm transfer initialisation!".to_string());
        }

        let sequence_count =
            file_size / (self.file_transfer_sequence_max_length * self.file_transfer_packet_size);
        let mut last_sequence_size = self.file_transfer_sequence_max_length;
        let partial_packet_byte_count = file_size % self.file_transfer_packet_size;

        let mut sequence_count = sequence_count;

        if !file_size
            .is_multiple_of(self.file_transfer_sequence_max_length * self.file_transfer_packet_size)
        {
            sequence_count += 1;
            let last_sequence_bytes = file_size
                % (self.file_transfer_sequence_max_length * self.file_transfer_packet_size);
            last_sequence_size = last_sequence_bytes / self.file_transfer_packet_size;
            if partial_packet_byte_count != 0 {
                last_sequence_size += 1;
            }
        }

        let mut bytes_transferred = 0u32;
        let mut previous_percent = 0u32;
        println!("0%");

        let mut file_buffer = vec![0u8; self.file_transfer_packet_size as usize];

        for sequence_index in 0..sequence_count {
            let is_last_sequence = sequence_index == sequence_count - 1;
            let sequence_size = if is_last_sequence {
                last_sequence_size
            } else {
                self.file_transfer_sequence_max_length
            };
            let sequence_total_byte_count = sequence_size * self.file_transfer_packet_size;

            let packet =
                packets::OutboundPacket::flash_part_file_transfer(sequence_total_byte_count);
            self.send_packet(&packet, 3000, EmptyTransferMode::After)
                .map_err(|_| "Failed to begin file transfer sequence!".to_string())?;

            let response = self
                .receive_packet(3000, EmptyTransferMode::None)
                .map_err(|_| {
                    "Failed to confirm beginning of file transfer sequence!".to_string()
                })?;

            if response.response_type != packets::RESPONSE_TYPE_FILE_TRANSFER {
                return Err("Failed to confirm beginning of file transfer sequence!".to_string());
            }

            for file_part_index in 0..sequence_size {
                let send_empty_transfer_mode = if file_part_index == 0 {
                    EmptyTransferMode::None
                } else {
                    EmptyTransferMode::Before
                };

                let packet_byte_count = if is_last_sequence
                    && file_part_index == sequence_size - 1
                    && partial_packet_byte_count != 0
                {
                    partial_packet_byte_count
                } else {
                    self.file_transfer_packet_size
                };

                // Read data from reader
                file_buffer.fill(0);
                reader
                    .read_exact(&mut file_buffer[..packet_byte_count as usize])
                    .map_err(|e| format!("Failed to read from file: {}", e))?;

                let packet = packets::create_send_file_part_packet(
                    &file_buffer,
                    self.file_transfer_packet_size,
                );
                self.send_raw_packet(&packet, 3000, send_empty_transfer_mode)
                    .map_err(|_| "Failed to send file part packet!".to_string())?;

                // Response
                let response_result = self.receive_packet(
                    self.file_transfer_sequence_timeout as i32,
                    EmptyTransferMode::None,
                );
                let mut success = response_result.is_ok();

                if success {
                    let response = response_result.unwrap();
                    let received_part_index =
                        if response.response_type == packets::RESPONSE_TYPE_SEND_FILE_PART {
                            response.value
                        } else {
                            success = false;
                            0
                        };
                    if success && received_part_index != file_part_index {
                        println!();
                        return Err(format!(
                            "Expected file part index: {} Received: {}",
                            file_part_index, received_part_index
                        ));
                    }
                }

                if !success {
                    let mut retry_success = false;
                    for _ in 0..4 {
                        println!("\nRetrying...");

                        // Rewind reader pointer
                        reader
                            .seek(std::io::SeekFrom::Start(bytes_transferred as u64))
                            .map_err(|e| format!("Failed to seek in file: {}", e))?;
                        reader
                            .read_exact(&mut file_buffer[..packet_byte_count as usize])
                            .map_err(|e| format!("Failed to read from file: {}", e))?;

                        let packet = packets::create_send_file_part_packet(
                            &file_buffer,
                            self.file_transfer_packet_size,
                        );
                        if self
                            .send_raw_packet(&packet, 3000, send_empty_transfer_mode)
                            .is_err()
                        {
                            continue;
                        }

                        let res = self.receive_packet(
                            self.file_transfer_sequence_timeout as i32,
                            EmptyTransferMode::None,
                        );

                        if let Ok(response) = res {
                            let received_part_index = if response.response_type
                                == packets::RESPONSE_TYPE_SEND_FILE_PART
                            {
                                response.value
                            } else {
                                success = false;
                                0
                            };
                            if success && received_part_index == file_part_index {
                                retry_success = true;
                                break;
                            }
                        }
                    }

                    if !retry_success {
                        println!();
                        return Err("Failed to receive file part response!".to_string());
                    }
                }

                bytes_transferred += packet_byte_count;
                let current_percent =
                    (100.0f32 * (bytes_transferred as f32 / file_size as f32)) as u32;

                if current_percent != previous_percent {
                    println!("\n{}%", current_percent);
                    previous_percent = current_percent;
                }
            }

            let sequence_effective_byte_count =
                if is_last_sequence && partial_packet_byte_count != 0 {
                    self.file_transfer_packet_size * (last_sequence_size - 1)
                        + partial_packet_byte_count
                } else {
                    sequence_total_byte_count
                };

            let packet = match pit_entry.binary_type {
                BinaryType::CommunicationProcessor => {
                    packets::OutboundPacket::end_modem_file_transfer(
                        sequence_effective_byte_count,
                        pit_entry.binary_type as u32,
                        pit_entry.device_type as u32,
                        is_last_sequence,
                    )
                }
                BinaryType::ApplicationProcessor => {
                    packets::OutboundPacket::end_phone_file_transfer(
                        sequence_effective_byte_count,
                        pit_entry.binary_type as u32,
                        pit_entry.device_type as u32,
                        pit_entry.identifier,
                        is_last_sequence,
                    )
                }
            };

            self.send_packet(&packet, 3000, EmptyTransferMode::BeforeAndAfter)
                .map_err(|_| "Failed to end file transfer sequence!".to_string())?;

            let response = self
                .receive_packet(
                    self.file_transfer_sequence_timeout as i32,
                    EmptyTransferMode::None,
                )
                .map_err(|_| "Failed to confirm end of file transfer sequence!".to_string())?;

            if response.response_type != packets::RESPONSE_TYPE_FILE_TRANSFER {
                return Err("Failed to confirm end of file transfer sequence!".to_string());
            }
        }

        Ok(())
    }

    pub(crate) fn set_total_bytes(&self, total_bytes: u64) -> Result<(), String> {
        let packet = packets::OutboundPacket::total_bytes(total_bytes);
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
            .map_err(|_| "Failed to send total bytes packet!".to_string())?;

        let response = self.receive_packet(3000, EmptyTransferMode::None)?;

        if response.response_type != packets::RESPONSE_TYPE_SESSION_SETUP {
            return Err("Failed to unpack session setup response!".to_string());
        }

        if response.value != 0 {
            return Err(format!(
                "Unexpected session total bytes response!\nExpected: 0\nReceived: {}",
                response.value
            ));
        }

        Ok(())
    }
}

impl Drop for BridgeManager {
    fn drop(&mut self) {
        if self.interface_claimed {
            self.release_device_interface();
        }
    }
}
