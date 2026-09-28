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

use super::*;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use ::nusb::transfer::{Buffer, BulkOrInterrupt, Completion, EndpointDirection};
use futures_timer::Delay;

struct TransferFuture<'a, EpType: BulkOrInterrupt, Dir: EndpointDirection> {
    ep: &'a mut ::nusb::Endpoint<EpType, Dir>,
    #[cfg(not(target_arch = "wasm32"))]
    delay: Delay,
    #[cfg(not(target_arch = "wasm32"))]
    cancelled: bool,
}

impl<'a, EpType: BulkOrInterrupt, Dir: EndpointDirection> Future
    for TransferFuture<'a, EpType, Dir>
{
    type Output = Completion;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Poll::Ready(completion) = this.ep.poll_next_complete(cx) {
                return Poll::Ready(completion);
            }
            if !this.cancelled && Pin::new(&mut this.delay).poll(cx).is_ready() {
                this.ep.cancel_all();
                this.cancelled = true;
                if let Poll::Ready(completion) = this.ep.poll_next_complete(cx) {
                    return Poll::Ready(completion);
                }
            }
            Poll::Pending
        }
        #[cfg(target_arch = "wasm32")]
        {
            this.ep.poll_next_complete(cx)
        }
    }
}

async fn transfer_async<EpType: BulkOrInterrupt, Dir: EndpointDirection>(
    ep: &mut ::nusb::Endpoint<EpType, Dir>,
    buf: Buffer,
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))] timeout: Duration,
) -> Completion {
    assert_eq!(ep.pending(), 0, "a transfer is already pending");
    ep.submit(buf);
    TransferFuture {
        ep,
        #[cfg(not(target_arch = "wasm32"))]
        delay: Delay::new(timeout),
        #[cfg(not(target_arch = "wasm32"))]
        cancelled: false,
    }
    .await
}

/// USB communication backend using `nusb`.
pub struct NusbBackend {
    verbose: bool,
    ep_in: ::nusb::Endpoint<::nusb::transfer::Bulk, ::nusb::transfer::In>,
    ep_out: ::nusb::Endpoint<::nusb::transfer::Bulk, ::nusb::transfer::Out>,
    product: Option<String>,
}

impl NusbBackend {
    fn print_device_info(device: &::nusb::DeviceInfo) {
        if let Some(manufacturer) = device.manufacturer_string() {
            eprintln!("      Manufacturer: \"{}\"", manufacturer);
        }
        if let Some(product) = device.product_string() {
            eprintln!("           Product: \"{}\"", product);
        }
        if let Some(serial) = device.serial_number() {
            eprintln!("         Serial No: \"{}\"", serial);
        }

        eprintln!("\n      device class: {}", device.class());
        eprintln!(
            "           VID:PID: {:04X}:{:04X}",
            device.vendor_id(),
            device.product_id()
        );
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl UsbBackend for NusbBackend {
    type UsbDevice = ::nusb::DeviceInfo;

    async fn new(device: Self::UsbDevice, verbose: bool) -> Result<Self, OdinError> {
        let handle = device
            .open()
            .await
            .map_err(|e| OdinError::DeviceAccess(Box::new(e)))?;

        // Traverse configuration and select the class USB_CLASS_CDC_DATA interface with 2 endpoints
        let mut interface_index = -1;
        let mut alt_setting_index = -1;
        let mut in_endpoint = 0;
        let mut out_endpoint = 0;

        if let Ok(config) = handle.active_configuration() {
            for interface in config.interface_alt_settings() {
                let mut in_endpoint_address = None;
                let mut out_endpoint_address = None;

                for endpoint in interface.endpoints() {
                    let addr = endpoint.address();
                    if addr & 0x80 != 0 {
                        in_endpoint_address = Some(addr);
                    } else {
                        out_endpoint_address = Some(addr);
                    }
                }

                if interface_index < 0
                    && interface.endpoints().count() == 2
                    && interface.class() == USB_CLASS_CDC_DATA
                    && let (Some(in_addr), Some(out_addr)) =
                        (in_endpoint_address, out_endpoint_address)
                {
                    interface_index = interface.interface_number() as i32;
                    alt_setting_index = interface.alternate_setting() as i32;
                    in_endpoint = in_addr;
                    out_endpoint = out_addr;
                }
            }
        }

        if interface_index < 0 {
            return Err(OdinError::InterfaceConfigurationNotFound);
        }

        if verbose {
            Self::print_device_info(&device);
        }

        let interface = handle
            .detach_and_claim_interface(interface_index as u8)
            .await
            .map_err(|_| OdinError::InterfaceClaimFailed)?;

        if alt_setting_index != 0 {
            interface
                .set_alt_setting(alt_setting_index as u8)
                .await
                .map_err(|_| OdinError::InterfaceSetupFailed)?;
        }

        let ep_in = interface
            .endpoint::<::nusb::transfer::Bulk, ::nusb::transfer::In>(in_endpoint)
            .map_err(|e| OdinError::SerialError(format!("Failed to open IN endpoint: {}", e)))?;
        let ep_out = interface
            .endpoint::<::nusb::transfer::Bulk, ::nusb::transfer::Out>(out_endpoint)
            .map_err(|e| OdinError::SerialError(format!("Failed to open OUT endpoint: {}", e)))?;

        let product = device.product_string().map(|s| s.to_string());

        Ok(Self {
            verbose,
            ep_in,
            ep_out,
            product,
        })
    }

    async fn find_device<'a, F>(wait: bool, mut predicate: F) -> Result<Self::UsbDevice, OdinError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a,
    {
        let mut print_wait = false;
        loop {
            if let Ok(devices) = ::nusb::list_devices().await {
                for device in devices {
                    if predicate(device.vendor_id(), device.product_id()) {
                        return Ok(device);
                    }
                }
            }
            if wait && !print_wait {
                println!("Waiting for device...");
                print_wait = true;
                Delay::new(Duration::from_secs(1)).await;
            } else {
                break;
            }
        }
        Err(OdinError::DeviceNotFound)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl UsbTransfer for NusbBackend {
    async fn reset(&mut self) {
        if let Err(e) = self.ep_in.clear_halt().await {
            print_warning!(self.verbose, "Failed to clear IN endpoint halt: {}", e);
        }
        if let Err(e) = self.ep_out.clear_halt().await {
            print_warning!(self.verbose, "Failed to clear OUT endpoint halt: {}", e);
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let max_packet_size = self.ep_in.max_packet_size();
            let buf_size = if max_packet_size > 0 {
                max_packet_size
            } else {
                1024
            };
            loop {
                let buf = Buffer::new(buf_size);
                let completion =
                    transfer_async(&mut self.ep_in, buf, Duration::from_millis(10)).await;
                match completion.status {
                    Ok(()) if completion.actual_len > 0 => continue,
                    _ => break,
                }
            }
        }
    }

    async fn send_data(&mut self, data: &[u8], timeout: i32, retry: bool) -> bool {
        let max_attempts = if retry { 6 } else { 1 };
        for attempt in 0..max_attempts {
            if attempt > 0 {
                Delay::new(Duration::from_millis(250 * attempt)).await;
            }
            let buf = Buffer::from(data.to_vec());
            let completion =
                transfer_async(&mut self.ep_out, buf, Duration::from_millis(timeout as u64)).await;
            if completion.status.is_ok() {
                return completion.actual_len == data.len();
            }
        }
        false
    }

    async fn receive_data(&mut self, data: &mut [u8], timeout: i32, retry: bool) -> i32 {
        let max_attempts = if retry { 6 } else { 1 };
        for attempt in 0..max_attempts {
            if attempt > 0 {
                Delay::new(Duration::from_millis(250 * attempt)).await;
            }
            let max_packet_size = self.ep_in.max_packet_size();
            let mut requested_len = data.len();
            if !requested_len.is_multiple_of(max_packet_size) {
                requested_len = ((requested_len / max_packet_size) + 1) * max_packet_size;
            }
            let buf = Buffer::new(requested_len);
            let completion =
                transfer_async(&mut self.ep_in, buf, Duration::from_millis(timeout as u64)).await;
            if let Ok(()) = completion.status {
                let to_copy = std::cmp::min(completion.actual_len, data.len());
                data[..to_copy].copy_from_slice(&completion.buffer[..to_copy]);
                return to_copy as i32;
            }
        }
        -1
    }

    fn product_name(&self) -> Option<&str> {
        self.product.as_deref()
    }
}
