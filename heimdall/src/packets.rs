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

use binrw::{io::Cursor, BinRead, BinWrite};

pub const RESPONSE_TYPE_SEND_FILE_PART: u32 = 0x00;
pub const RESPONSE_TYPE_SESSION_SETUP: u32 = 0x64;
pub const RESPONSE_TYPE_PIT_FILE: u32 = 0x65;
pub const RESPONSE_TYPE_FILE_TRANSFER: u32 = 0x66;
pub const RESPONSE_TYPE_END_SESSION: u32 = 0x67;

#[derive(BinWrite)]
#[brw(little)]
pub(crate) enum OutboundPacket {
    #[brw(magic = 0x64u32)]
    Session(SessionRequest),

    #[brw(magic = 0x65u32)]
    PitFile(PitFileRequest),

    #[brw(magic = 0x66u32)]
    FileTransfer(FileTransferRequest),

    #[brw(magic = 0x67u32)]
    EndSession {
        request: u32,
        #[brw(pad_after = 1016)]
        _padding: (),
    },
}

#[derive(BinWrite)]
#[brw(little)]
pub(crate) enum SessionRequest {
    #[brw(magic = 0u32)]
    Begin {
        protocol_version: u32,
        #[brw(pad_after = 1012)]
        _padding: (),
    },
    #[brw(magic = 2u32)]
    TotalBytes {
        total_bytes: u64,
        #[brw(pad_after = 1008)]
        _padding: (),
    },
    #[brw(magic = 5u32)]
    FilePartSize {
        size: u32,
        #[brw(pad_after = 1012)]
        _padding: (),
    },
}

#[derive(BinWrite)]
#[brw(little)]
pub(crate) enum PitFileRequest {
    #[brw(magic = 0u32)]
    Flash {
        #[brw(pad_after = 1016)]
        _padding: (),
    },
    #[brw(magic = 1u32)]
    Dump {
        #[brw(pad_after = 1016)]
        _padding: (),
    },
    #[brw(magic = 2u32)]
    Part(PitFilePart),
    #[brw(magic = 3u32)]
    End {
        size: u32,
        #[brw(pad_after = 1012)]
        _padding: (),
    },
}

#[derive(BinWrite)]
#[brw(little)]
pub(crate) enum PitFilePart {
    Flash {
        size: u32,
        #[brw(pad_after = 1012)]
        _padding: (),
    },
    Dump {
        part: u32,
        #[brw(pad_after = 1012)]
        _padding: (),
    },
}

#[derive(BinWrite)]
#[brw(little)]
pub(crate) enum FileTransferRequest {
    #[brw(magic = 0u32)]
    Flash {
        #[brw(pad_after = 1016)]
        _padding: (),
    },
    #[brw(magic = 1u32)]
    Dump {
        #[brw(pad_after = 1016)]
        _padding: (),
    },
    #[brw(magic = 2u32)]
    Part {
        sequence_byte_count: u32,
        #[brw(pad_after = 1012)]
        _padding: (),
    },
    #[brw(magic = 3u32)]
    End(FileTransferEnd),
}

#[derive(BinWrite)]
#[brw(little)]
pub(crate) enum FileTransferEnd {
    #[brw(magic = 0u32)]
    Phone {
        sequence_byte_count: u32,
        binary_type: u32,
        device_type: u32,
        partition_identifier: u32,
        is_last_sequence: u32,
        #[brw(pad_after = 992)]
        _padding: (),
    },
    #[brw(magic = 1u32)]
    Modem {
        sequence_byte_count: u32,
        binary_type: u32,
        device_type: u32,
        is_last_sequence: u32,
        #[brw(pad_after = 996)]
        _padding: (),
    },
}

impl OutboundPacket {
    pub(crate) fn begin_session() -> OutboundPacket {
        OutboundPacket::Session(SessionRequest::Begin {
            protocol_version: 0x04,
            _padding: (),
        })
    }

    pub(crate) fn total_bytes(total_bytes: u64) -> OutboundPacket {
        OutboundPacket::Session(SessionRequest::TotalBytes {
            total_bytes,
            _padding: (),
        })
    }

    pub(crate) fn file_part_size(size: u32) -> OutboundPacket {
        OutboundPacket::Session(SessionRequest::FilePartSize { size, _padding: () })
    }

    pub(crate) fn end_session(request: u32) -> OutboundPacket {
        OutboundPacket::EndSession {
            request,
            _padding: (),
        }
    }

    pub(crate) fn pit_file_flash() -> OutboundPacket {
        OutboundPacket::PitFile(PitFileRequest::Flash { _padding: () })
    }

    pub(crate) fn pit_file_dump() -> OutboundPacket {
        OutboundPacket::PitFile(PitFileRequest::Dump { _padding: () })
    }

    pub(crate) fn pit_file_end() -> OutboundPacket {
        OutboundPacket::PitFile(PitFileRequest::End {
            size: 0,
            _padding: (),
        })
    }

    pub(crate) fn flash_part_pit_file(size: u32) -> OutboundPacket {
        OutboundPacket::PitFile(PitFileRequest::Part(PitFilePart::Flash {
            size,
            _padding: (),
        }))
    }

    pub(crate) fn dump_part_pit_file(part: u32) -> OutboundPacket {
        OutboundPacket::PitFile(PitFileRequest::Part(PitFilePart::Dump {
            part,
            _padding: (),
        }))
    }

    pub(crate) fn end_pit_file_transfer(size: u32) -> OutboundPacket {
        OutboundPacket::PitFile(PitFileRequest::End { size, _padding: () })
    }

    pub(crate) fn file_transfer_flash() -> OutboundPacket {
        OutboundPacket::FileTransfer(FileTransferRequest::Flash { _padding: () })
    }

    pub(crate) fn file_transfer_dump() -> OutboundPacket {
        OutboundPacket::FileTransfer(FileTransferRequest::Dump { _padding: () })
    }

    pub(crate) fn flash_part_file_transfer(sequence_byte_count: u32) -> OutboundPacket {
        OutboundPacket::FileTransfer(FileTransferRequest::Part {
            sequence_byte_count,
            _padding: (),
        })
    }

    pub(crate) fn end_modem_file_transfer(
        sequence_byte_count: u32,
        binary_type: u32,
        device_type: u32,
        is_last_sequence: bool,
    ) -> OutboundPacket {
        OutboundPacket::FileTransfer(FileTransferRequest::End(FileTransferEnd::Modem {
            sequence_byte_count,
            binary_type,
            device_type,
            is_last_sequence: if is_last_sequence { 1 } else { 0 },
            _padding: (),
        }))
    }

    pub(crate) fn end_phone_file_transfer(
        sequence_byte_count: u32,
        binary_type: u32,
        device_type: u32,
        partition_identifier: u32,
        is_last_sequence: bool,
    ) -> OutboundPacket {
        OutboundPacket::FileTransfer(FileTransferRequest::End(FileTransferEnd::Phone {
            sequence_byte_count,
            binary_type,
            device_type,
            partition_identifier,
            is_last_sequence: if is_last_sequence { 1 } else { 0 },
            _padding: (),
        }))
    }

    pub(crate) fn pack(&self) -> Vec<u8> {
        let mut writer = Cursor::new(Vec::with_capacity(1024));
        self.write_le(&mut writer).expect("Failed to write packet");
        writer.into_inner()
    }
}

#[derive(BinRead)]
#[brw(little)]
pub(crate) struct Response {
    pub response_type: u32,
    pub value: u32,
}

pub(crate) fn create_send_file_part_packet(buffer: &[u8], size: u32) -> Vec<u8> {
    let mut data = vec![0u8; size as usize];
    let bytes_to_copy = std::cmp::min(buffer.len(), size as usize);
    data[..bytes_to_copy].copy_from_slice(&buffer[..bytes_to_copy]);
    data
}
