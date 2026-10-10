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

//! Platform-independent readahead for memory-mapped firmware payloads.
//!
//! A helper thread reads a bounded window ahead of the USB transmission position
//! using bulk file reads. This warms the shared file cache without serializing
//! small memory-mapped page faults over high-latency network filesystems.

use crate::odin::MAX_SLICE_SIZE;
use std::fs::File;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

/// Number of slices to keep read ahead of the slice currently being transmitted.
const READAHEAD_SLICES: usize = 1;
const READAHEAD_WINDOW: usize = READAHEAD_SLICES * MAX_SLICE_SIZE;

// Smallest page size of supported platforms; touching more often than needed is harmless.
const PAGE_SIZE: usize = 4096;
const READ_SIZE: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct Mapping<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) source: Option<&'a File>,
    pub(crate) offset: u64,
}

#[cfg(test)]
impl<'a> From<&'a [u8]> for Mapping<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self {
            data,
            source: None,
            offset: 0,
        }
    }
}

struct Request<'a> {
    data: &'a [u8],
    source: Option<&'a File>,
    offset: u64,
}

/// Tracks the readahead frontier over the payloads of a flash session, in flashing order.
pub(crate) struct Readahead<'a> {
    tx: Sender<Request<'a>>,
    stop: &'a AtomicBool,
    mappings: Vec<Mapping<'a>>,
    window: usize,
    // Everything before (frontier_idx, frontier_off) has already been requested.
    frontier_idx: usize,
    frontier_off: usize,
}

impl<'a> Readahead<'a> {
    fn new(
        tx: Sender<Request<'a>>,
        stop: &'a AtomicBool,
        mappings: Vec<Mapping<'a>>,
        window: usize,
    ) -> Self {
        Self {
            tx,
            stop,
            mappings,
            window,
            frontier_idx: 0,
            frontier_off: 0,
        }
    }

    /// Returns a handle for the payload at `idx` in flashing order.
    pub(crate) fn payload(&mut self, idx: usize) -> ReadaheadPayload<'_, 'a> {
        ReadaheadPayload { ra: self, idx }
    }

    /// Requests everything up to `window` bytes past `pos` within payload `idx`,
    /// continuing into the following payloads if needed.
    fn advance(&mut self, idx: usize, pos: usize) {
        let (target_idx, target_off) = self.locate(idx, pos, self.window);

        while (self.frontier_idx, self.frontier_off) < (target_idx, target_off) {
            let mapping = self.mappings[self.frontier_idx];
            let data = mapping.data;
            let end = if self.frontier_idx == target_idx {
                target_off
            } else {
                data.len()
            };

            if end > self.frontier_off {
                // The worker may have exited; requests are only hints.
                let _ = self.tx.send(Request {
                    data: &data[self.frontier_off..end],
                    source: mapping.source,
                    offset: mapping.offset + self.frontier_off as u64,
                });
            }

            if end == data.len() {
                self.frontier_idx += 1;
                self.frontier_off = 0;
            } else {
                self.frontier_off = end;
            }
        }
    }

    /// Returns the position `len` bytes past `pos` within payload `idx`, clamped
    /// to the end of the last payload.
    fn locate(&self, mut idx: usize, pos: usize, len: usize) -> (usize, usize) {
        let mut off = pos;
        let mut remaining = len;
        while let Some(mapping) = self.mappings.get(idx) {
            let data = mapping.data;
            let avail = data.len().saturating_sub(off);
            if remaining < avail {
                return (idx, off + remaining);
            }
            remaining -= avail;
            idx += 1;
            off = 0;
        }
        (self.mappings.len(), 0)
    }
}

impl Drop for Readahead<'_> {
    fn drop(&mut self) {
        // Discard any queued requests; the sender is dropped right after.
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A [`Readahead`] handle bound to a single payload.
pub(crate) struct ReadaheadPayload<'r, 'a> {
    ra: &'r mut Readahead<'a>,
    idx: usize,
}

impl ReadaheadPayload<'_, '_> {
    /// Notifies that the payload has been consumed up to byte offset `pos`.
    pub(crate) fn advance(&mut self, pos: usize) {
        self.ra.advance(self.idx, pos);
    }

    /// Notifies that `slice`, a subslice of the payload, is about to be consumed.
    /// Slices that do not point into the payload are ignored.
    pub(crate) fn advance_past(&mut self, slice: &[u8]) {
        let data = self.ra.mappings[self.idx].data.as_ptr_range();
        let slice = slice.as_ptr_range();
        if data.start <= slice.start && slice.end <= data.end {
            let end = slice.end as usize - data.start as usize;
            self.advance(end);
        }
    }
}

/// Runs `f` with a [`Readahead`] over `mappings`, backed by a helper thread that
/// is joined before returning.
pub(crate) fn scope<R>(mappings: Vec<Mapping<'_>>, f: impl FnOnce(&mut Readahead<'_>) -> R) -> R {
    scope_with_window(mappings, READAHEAD_WINDOW, f)
}

fn scope_with_window<R>(
    mappings: Vec<Mapping<'_>>,
    window: usize,
    f: impl FnOnce(&mut Readahead<'_>) -> R,
) -> R {
    let stop = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel();

    thread::scope(|s| {
        let stop = &stop;
        // If the thread cannot be spawned, requests are dropped and flashing
        // proceeds without readahead.
        let _ = thread::Builder::new()
            .name("odin-readahead".into())
            .spawn_scoped(s, move || worker(rx, stop));

        let mut ra = Readahead::new(tx, stop, mappings, window);
        f(&mut ra)
    })
}

fn worker(rx: Receiver<Request<'_>>, stop: &AtomicBool) {
    let mut buffer = vec![0u8; READ_SIZE];
    for request in rx {
        let mut pos = 0;
        if let Some(source) = request.source {
            while pos < request.data.len() {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let len = buffer.len().min(request.data.len() - pos);
                match read_at(source, &mut buffer[..len], request.offset + pos as u64) {
                    Ok(0) => break,
                    Ok(n) => pos += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    // Readahead is advisory; fall back to touching the mapping.
                    Err(_) => break,
                }
            }
        }
        for i in (0..request.data.len()).step_by(PAGE_SIZE) {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            // SAFETY: `i` is in bounds, so the pointer is valid for reads. The
            // volatile read keeps the page fault from being optimized away.
            unsafe { std::ptr::read_volatile(request.data.as_ptr().add(i)) };
        }
    }
}

fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(buffer, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(buffer, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offsets(base: &[u8], requests: &[&[u8]]) -> Vec<(usize, usize)> {
        let start = base.as_ptr() as usize;
        requests
            .iter()
            .map(|r| {
                let off = r.as_ptr() as usize - start;
                (off, off + r.len())
            })
            .collect()
    }

    // Three payloads laid out back to back in one buffer so that requests can be
    // identified by offset: [0, 10), [10, 15), [15, 35).
    fn with_readahead(
        window: usize,
        f: impl for<'b> FnOnce(&mut Readahead<'b>, &Receiver<Request<'b>>),
    ) {
        let buf = [0u8; 35];
        let mappings = vec![
            (&buf[0..10]).into(),
            (&buf[10..15]).into(),
            (&buf[15..35]).into(),
        ];
        let stop = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel();
        let mut ra = Readahead::new(tx, &stop, mappings, window);
        f(&mut ra, &rx);
    }

    fn drain(base: &[u8], rx: &Receiver<Request<'_>>) -> Vec<(usize, usize)> {
        let requests: Vec<&[u8]> = rx.try_iter().map(|r| r.data).collect();
        offsets(base, &requests)
    }

    #[test]
    fn test_advance_spans_payloads() {
        with_readahead(12, |ra, rx| {
            let base = ra.mappings[0].data;

            ra.payload(0).advance(0);
            assert_eq!(drain(base, rx), vec![(0, 10), (10, 12)]);

            ra.payload(0).advance(10);
            assert_eq!(drain(base, rx), vec![(12, 15), (15, 22)]);

            ra.payload(2).advance(5);
            assert_eq!(drain(base, rx), vec![(22, 32)]);
        });
    }

    #[test]
    fn test_requests_preserve_archive_offsets_across_payloads() {
        let source = File::open(std::env::current_exe().unwrap()).unwrap();
        let buf = [0u8; 20];
        let mappings = vec![
            Mapping {
                data: &buf[..10],
                source: Some(&source),
                offset: 512,
            },
            Mapping {
                data: &buf[10..],
                source: Some(&source),
                offset: 4096,
            },
        ];
        let stop = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel();
        let mut ra = Readahead::new(tx, &stop, mappings, 12);
        ra.payload(0).advance(0);
        let requests: Vec<_> = rx.try_iter().collect();
        assert_eq!(requests.len(), 2);
        assert_eq!((requests[0].offset, requests[0].data.len()), (512, 10));
        assert_eq!((requests[1].offset, requests[1].data.len()), (4096, 2));
        assert!(
            requests
                .iter()
                .all(|r| std::ptr::eq(r.source.unwrap(), &source))
        );
        ra.payload(0).advance(10);
        let request = rx.try_recv().unwrap();
        assert_eq!((request.offset, request.data.len()), (4098, 8));
    }

    #[test]
    fn test_advance_never_rerequests() {
        with_readahead(12, |ra, rx| {
            let base = ra.mappings[0].data;

            ra.payload(0).advance(8);
            assert_eq!(drain(base, rx), vec![(0, 10), (10, 15), (15, 20)]);

            // Behind or within the frontier: nothing new
            ra.payload(0).advance(2);
            ra.payload(0).advance(8);
            assert!(drain(base, rx).is_empty());
        });
    }

    #[test]
    fn test_advance_clamps_to_end() {
        with_readahead(100, |ra, rx| {
            let base = ra.mappings[0].data;

            ra.payload(1).advance(3);
            assert_eq!(drain(base, rx), vec![(0, 10), (10, 15), (15, 35)]);

            ra.payload(2).advance(20);
            assert!(drain(base, rx).is_empty());
        });
    }

    #[test]
    fn test_advance_skips_empty_payloads() {
        let buf = vec![0u8; 8];
        let mappings = vec![
            (&buf[0..4]).into(),
            (&buf[4..4]).into(),
            (&buf[4..8]).into(),
        ];
        let stop = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel();
        let mut ra = Readahead::new(tx, &stop, mappings, 6);

        ra.payload(0).advance(0);
        assert_eq!(drain(&buf, &rx), vec![(0, 4), (4, 6)]);
    }

    #[test]
    fn test_advance_past_subslice() {
        with_readahead(3, |ra, rx| {
            let base = ra.mappings[0].data;
            let payload = ra.mappings[2].data;

            ra.payload(2).advance_past(&payload[0..4]);
            assert_eq!(drain(base, rx), vec![(0, 10), (10, 15), (15, 22)]);

            // Slices outside the payload are ignored
            let foreign = vec![0u8; 4];
            ra.payload(2).advance_past(&foreign);
            ra.payload(2).advance_past(&base[0..4]);
            assert!(drain(base, rx).is_empty());
        });
    }

    #[test]
    fn test_scope_joins_worker() {
        let buf = vec![1u8; 4 * PAGE_SIZE + 1];
        let result = scope_with_window(vec![(&buf[..]).into()], PAGE_SIZE, |ra| {
            let mut payload = ra.payload(0);
            payload.advance(0);
            payload.advance(buf.len());
            42
        });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_worker_exits_on_stop() {
        let buf = vec![0u8; 16 * PAGE_SIZE];
        let stop = AtomicBool::new(true);
        let (tx, rx) = mpsc::channel();
        tx.send(Request {
            data: &buf,
            source: None,
            offset: 0,
        })
        .unwrap();
        // Sender is kept alive: the worker must return because of the stop flag alone.
        worker(rx, &stop);
        drop(tx);
    }

    #[test]
    fn test_worker_exits_on_disconnect() {
        let buf = vec![0u8; 3 * PAGE_SIZE];
        let stop = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel();
        tx.send(Request {
            data: &buf,
            source: None,
            offset: 0,
        })
        .unwrap();
        tx.send(Request {
            data: &buf[1..2],
            source: None,
            offset: 0,
        })
        .unwrap();
        drop(tx);
        worker(rx, &stop);
    }
}
