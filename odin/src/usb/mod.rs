// Copyright 2026 John "topjohnwu" Wu
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

#[cfg(not(any(
    feature = "rusb",
    feature = "nusb",
    feature = "serialport",
    feature = "mock",
    debug_assertions
)))]
compile_error!("At least one USB backend must be enabled!");

use crate::error::OdinError;
use std::time::Duration;

#[cfg(feature = "rusb")]
use ::rusb::{Context, DeviceHandle, UsbContext};

#[cfg(feature = "serialport")]
use std::io::{Read, Write};

#[allow(unused_macros)]
macro_rules! print_warning {
    ($($arg:tt)*) => {
        crate::progress::println_verbose(&format!("WARNING: {}", format_args!($($arg)*)));
    };
}

#[allow(unused_macros)]
macro_rules! print_verbose {
    ($($arg:tt)*) => {
        crate::progress::println_verbose(&format!($($arg)*));
    };
}

pub(crate) const VID_SAMSUNG: u16 = 0x04E8;
const PID_GALAXY_S: u16 = 0x6601;
const PID_GALAXY_S2: u16 = 0x685D;
const PID_DROID_CHARGE: u16 = 0x68C3;

const SUPPORTED_DEVICES: &[(u16, u16)] = &[
    (VID_SAMSUNG, PID_GALAXY_S),
    (VID_SAMSUNG, PID_GALAXY_S2),
    (VID_SAMSUNG, PID_DROID_CHARGE),
];

#[cfg(any(feature = "nusb", feature = "rusb"))]
const USB_CLASS_CDC_DATA: u8 = 0x0A;

/// Helper trait representing `Send` on non-WASM targets and unbounded on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

/// Helper trait representing `Send` on non-WASM targets and unbounded on WASM.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// Trait representing a duplex data transport layer for USB or serial communication.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait UsbTransfer: MaybeSend {
    /// Resets the transport connection state and buffers.
    async fn reset(&mut self);
    /// Sends a buffer of data across the transport with a timeout.
    async fn send_data(&mut self, data: &[u8], timeout: i32) -> bool;
    /// Receives data from the transport into a buffer, returning the number of bytes read.
    async fn receive_data(&mut self, data: &mut [u8], timeout: i32) -> i32;
    /// Returns the USB Product descriptor string if available.
    fn product_name(&self) -> Option<&str> {
        None
    }
}

/// Trait representing a backend factory and device locator for USB or serial transports.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait UsbBackend: Sized + UsbTransfer {
    /// The associated device type identifier.
    type UsbDevice: MaybeSend;

    /// Instantiates a new backend session wrapper for a given device.
    async fn new(device: Self::UsbDevice) -> Result<Self, OdinError>;
    /// Searches for a matching connected device based on a predicate.
    async fn find_device<'a, F>(predicate: F) -> Result<Self::UsbDevice, OdinError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a;

    /// Searches for a connected device in Download Mode.
    async fn find_download_device() -> Result<Self::UsbDevice, OdinError> {
        Self::find_device(|vid, pid| SUPPORTED_DEVICES.contains(&(vid, pid))).await
    }
}

#[cfg(feature = "rusb")]
pub use rusb::RusbBackend;

#[cfg(feature = "rusb")]
mod rusb;

#[cfg(feature = "serialport")]
pub use serial::SerialBackend;

#[cfg(feature = "serialport")]
mod serial;

#[cfg(feature = "nusb")]
pub use nusb::NusbBackend;

#[cfg(feature = "nusb")]
mod nusb;

#[cfg(any(feature = "mock", debug_assertions))]
#[allow(unused_imports)]
pub use mock::{DeviceProfile, DeviceProfileBuilder, MockBackend};

#[cfg(any(feature = "mock", debug_assertions))]
mod mock;

/// Supported USB backend options.
#[derive(Debug, Clone, Copy)]
pub enum UsbBackendOption {
    /// libusb (rusb) backend.
    #[cfg(feature = "rusb")]
    Libusb,
    /// Virtual COM port (serialport) backend.
    #[cfg(feature = "serialport")]
    Vcom,
    /// nusb backend.
    #[cfg(feature = "nusb")]
    Nusb,
    /// Mock backend.
    #[cfg(any(feature = "mock", debug_assertions))]
    Mock,
}

impl TryFrom<&str> for UsbBackendOption {
    type Error = OdinError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            #[cfg(feature = "rusb")]
            "libusb" => Ok(UsbBackendOption::Libusb),
            #[cfg(feature = "serialport")]
            "vcom" => Ok(UsbBackendOption::Vcom),
            #[cfg(feature = "nusb")]
            "nusb" => Ok(UsbBackendOption::Nusb),
            #[cfg(any(feature = "mock", debug_assertions))]
            "mock" => Ok(UsbBackendOption::Mock),
            _ => Err(OdinError::ParseError(format!("Unknown USB backend: {s}"))),
        }
    }
}

impl std::str::FromStr for UsbBackendOption {
    type Err = OdinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl UsbBackendOption {
    /// Returns the string representation of the backend option.
    pub const fn to_str(self) -> &'static str {
        match self {
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => "libusb",
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => "vcom",
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => "nusb",
            #[cfg(any(feature = "mock", debug_assertions))]
            UsbBackendOption::Mock => "mock",
        }
    }

    async fn check_device(self) -> Result<(), OdinError> {
        match self {
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => {
                SerialBackend::find_download_device().await?;
                Ok(())
            }
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => {
                NusbBackend::find_download_device().await?;
                Ok(())
            }
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => {
                RusbBackend::find_download_device().await?;
                Ok(())
            }
            #[cfg(any(feature = "mock", debug_assertions))]
            UsbBackendOption::Mock => Ok(()),
        }
    }

    async fn create_transfer(self) -> Result<Box<dyn UsbTransfer>, OdinError> {
        match self {
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => {
                let device = SerialBackend::find_download_device().await?;
                let backend = SerialBackend::new(device).await?;
                Ok(Box::new(backend))
            }
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => {
                let device = NusbBackend::find_download_device().await?;
                let backend = NusbBackend::new(device).await?;
                Ok(Box::new(backend))
            }
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => {
                let device = RusbBackend::find_download_device().await?;
                let backend = RusbBackend::new(device).await?;
                Ok(Box::new(backend))
            }
            #[cfg(any(feature = "mock", debug_assertions))]
            UsbBackendOption::Mock => {
                let backend = MockBackend::new();
                Ok(Box::new(backend))
            }
        }
    }
}

impl std::fmt::Display for UsbBackendOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

async fn poll_device<T, F, Fut>(wait: bool, mut f: F) -> Result<T, OdinError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OdinError>>,
{
    let mut print_wait = false;
    loop {
        match f().await {
            Ok(val) => return Ok(val),
            Err(OdinError::DeviceNotFound) if wait => {
                if !print_wait {
                    crate::progress::println("Waiting for device...");
                    print_wait = true;
                }
                futures_timer::Delay::new(Duration::from_secs(1)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Creates and initializes the requested USB/VCOM communication backend interface.
pub async fn create_backend(
    usb_backend: UsbBackendOption,
    wait: bool,
) -> Result<Box<dyn UsbTransfer>, OdinError> {
    poll_device(wait, || usb_backend.create_transfer()).await
}

/// Helper function to detect a compatible download-mode device on a given backend.
pub async fn detect_device(usb_backend: UsbBackendOption, wait: bool) -> bool {
    poll_device(wait, || usb_backend.check_device())
        .await
        .is_ok()
}

/// Helper function to prompt user pairing for a compatible download-mode device on WASM.
#[cfg(target_arch = "wasm32")]
pub async fn request_device(usb_backend: UsbBackendOption) -> Result<(), OdinError> {
    match usb_backend {
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb => {
            let selectors: Vec<::nusb::DeviceSelector> = SUPPORTED_DEVICES
                .iter()
                .map(|&(vid, pid)| ::nusb::DeviceSelector::all().with_vid_pid(vid, pid))
                .collect();

            ::nusb::request_device(&selectors)
                .await
                .map_err(|e| OdinError::DeviceAccess(Box::new(e)))?
                .ok_or(OdinError::DeviceNotFound)?;
            Ok(())
        }
        #[cfg(any(feature = "mock", debug_assertions))]
        UsbBackendOption::Mock => Ok(()),
    }
}
