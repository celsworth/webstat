// Loader thread: reads files sequentially, decompresses if needed, and emits LoaderMsg::Lines batches.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;

use crate::aggregator::messages::{push_blocking, LoaderMsg};
use crate::aggregator::{FileResumePlan, ProgressState, LOADER_BATCH_SIZE};
use crate::compression::CompressionType;

pub(crate) fn run_loader(
    files: Vec<(usize, String, FileResumePlan)>,
    mut tx: rtrb::Producer<LoaderMsg>,
    ps: Arc<ProgressState>,
) -> Result<()> {
    for (file_idx, filepath, plan) in files {
        push_blocking(&mut tx, LoaderMsg::FileStart { file_idx });

        let result = if plan.compression.is_compressed() {
            read_compressed(&filepath, &plan, &mut tx, &ps)
        } else {
            read_plain(&filepath, &plan, &mut tx, &ps)
        };

        match result {
            Ok((final_offset, completed)) => {
                push_blocking(
                    &mut tx,
                    LoaderMsg::FileDone {
                        file_idx,
                        final_offset,
                        completed,
                    },
                );
            }
            Err(e) => {
                push_blocking(&mut tx, LoaderMsg::Done);
                return Err(e);
            }
        }
    }

    push_blocking(&mut tx, LoaderMsg::Done);
    Ok(())
}

fn read_plain(
    filepath: &str,
    plan: &FileResumePlan,
    tx: &mut rtrb::Producer<LoaderMsg>,
    ps: &ProgressState,
) -> Result<(u64, bool)> {
    let mut file = File::open(filepath)?;
    if plan.offset > 0 {
        file.seek(std::io::SeekFrom::Start(plan.offset))?;
    }
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut line = String::new();
    let mut batch: Vec<(String, u64)> = Vec::with_capacity(LOADER_BATCH_SIZE);
    let mut bytes_read: u64 = 0;
    let mut reported: u64 = 0;

    loop {
        let line_start = plan.offset + bytes_read;
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        bytes_read += n as u64;
        batch.push((line.clone(), line_start));

        if batch.len() >= LOADER_BATCH_SIZE {
            let current_offset = plan.offset + bytes_read;
            let delta = bytes_read.saturating_sub(reported);
            ps.bytes_done.fetch_add(delta, Ordering::Relaxed);
            reported = bytes_read;
            push_blocking(
                tx,
                LoaderMsg::Lines {
                    batch: std::mem::take(&mut batch),
                    current_offset,
                },
            );
            batch = Vec::with_capacity(LOADER_BATCH_SIZE);
        }
    }

    if !batch.is_empty() {
        let current_offset = plan.offset + bytes_read;
        ps.bytes_done
            .fetch_add(bytes_read.saturating_sub(reported), Ordering::Relaxed);
        push_blocking(
            tx,
            LoaderMsg::Lines {
                batch,
                current_offset,
            },
        );
    }

    let final_offset = plan.offset + bytes_read;
    let completed = final_offset >= plan.stat_size;
    Ok((final_offset, completed))
}

fn read_compressed(
    filepath: &str,
    plan: &FileResumePlan,
    tx: &mut rtrb::Producer<LoaderMsg>,
    ps: &ProgressState,
) -> Result<(u64, bool)> {
    let file = File::open(filepath)?;
    let decoder: Box<dyn Read> = match plan.compression {
        CompressionType::Gz => Box::new(flate2::read::MultiGzDecoder::new(file)),
        CompressionType::Bz2 => Box::new(bzip2::read::MultiBzDecoder::new(file)),
        CompressionType::Br => Box::new(brotli::Decompressor::new(file, 1 << 20)),
        CompressionType::Plain => unreachable!(),
    };
    let mut reader = BufReader::with_capacity(1 << 20, decoder);
    let mut line = String::new();
    let mut batch: Vec<(String, u64)> = Vec::with_capacity(LOADER_BATCH_SIZE);
    let mut decoded_total: u64 = 0;
    let mut skip_remaining = plan.skip_decoded_prefix_bytes;
    let mut reported: u64 = 0;

    loop {
        let line_start = decoded_total;
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        decoded_total += n as u64;

        if skip_remaining > 0 {
            let consumed = (n as u64).min(skip_remaining);
            skip_remaining -= consumed;
            if skip_remaining > 0 || consumed == n as u64 {
                continue;
            }
        }

        batch.push((line.clone(), line_start));

        if batch.len() >= LOADER_BATCH_SIZE {
            let effective = decoded_total.saturating_sub(plan.skip_decoded_prefix_bytes);
            let delta = effective.saturating_sub(reported);
            ps.bytes_done.fetch_add(delta, Ordering::Relaxed);
            reported = effective;
            push_blocking(
                tx,
                LoaderMsg::Lines {
                    batch: std::mem::take(&mut batch),
                    current_offset: decoded_total,
                },
            );
            batch = Vec::with_capacity(LOADER_BATCH_SIZE);
        }
    }

    if !batch.is_empty() {
        let effective = decoded_total.saturating_sub(plan.skip_decoded_prefix_bytes);
        ps.bytes_done
            .fetch_add(effective.saturating_sub(reported), Ordering::Relaxed);
        push_blocking(
            tx,
            LoaderMsg::Lines {
                batch,
                current_offset: decoded_total,
            },
        );
    }

    // Update gz progress counters once the whole file is done.
    ps.gz_comp_done.fetch_add(plan.stat_size, Ordering::Relaxed);
    ps.gz_decoded_done
        .fetch_add(decoded_total, Ordering::Relaxed);

    Ok((decoded_total, true))
}
