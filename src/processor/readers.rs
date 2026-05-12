use super::*;

impl Processor {
    pub(super) fn process_plain_in_parallel_ranges(
        &self,
        filepath: &str,
        offset: u64,
        stat_size: u64,
    ) -> Result<(u64, RunAccumulators)> {
        let total_bytes = stat_size.saturating_sub(offset);
        if total_bytes == 0 {
            return Ok((
                0,
                RunAccumulators::new(
                    32,
                    self.hll_precision,
                    self.enable_top_urls,
                    self.enable_top_hosts,
                    self.enable_top_refs,
                ),
            ));
        }

        let workers = self.file_workers.max(1);
        let chunk = (total_bytes + workers as u64 - 1) / workers as u64;

        let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(workers);
        for i in 0..workers {
            let start = offset + (i as u64 * chunk);
            if start >= stat_size {
                break;
            }
            let end = (offset + ((i as u64 + 1) * chunk)).min(stat_size);
            ranges.push((start, end));
        }

        let db_path = self.db_path.clone();
        let geoip_db = self.geoip_db.clone();
        let worker_config = self.worker_config();
        let checkpoint_minutes = self.checkpoint_every.map(|d| d.as_secs() / 60).unwrap_or(0);

        let results: Vec<Result<(u64, RunAccumulators)>> = {
            ranges
                .par_iter()
                .enumerate()
                .map(|(idx, (start, end))| {
                    let db = Database::open(&db_path)?;
                    let geo = Geo::new(geoip_db.as_deref());
                    let ua = UaParser::new();
                    let mut worker = Processor::new(
                        db,
                        geo,
                        ua,
                        db_path.clone(),
                        geoip_db.clone(),
                        1,
                        worker_config.clone(),
                    );
                    worker.set_checkpoint_interval_minutes(checkpoint_minutes);
                    worker.process_plain_range(filepath, *start, *end, idx + 1, ranges.len())
                })
                .collect()
        };

        let mut total = 0u64;
        let mut run_acc = RunAccumulators::new(
            32,
            self.hll_precision,
            self.enable_top_urls,
            self.enable_top_hosts,
            self.enable_top_refs,
        );
        for r in results {
            let (lines_processed, range_acc) = r?;
            total += lines_processed;
            run_acc.merge_from(range_acc, self.hll_precision, self.topn_k);
        }

        Ok((total, run_acc))
    }

    pub(super) fn process_plain_range(
        &mut self,
        filepath: &str,
        start: u64,
        end: u64,
        _range_num: usize,
        _range_count: usize,
    ) -> Result<(u64, RunAccumulators)> {
        let file = File::open(filepath)?;
        let mut reader = BufReader::with_capacity(1 << 20, file);

        reader.seek(SeekFrom::Start(start))?;
        let mut pos = start;

        // If this chunk starts mid-line, skip the partial fragment so each
        // physical line is processed by exactly one worker.
        if start > 0 {
            let mut prev = [0u8; 1];
            reader.seek(SeekFrom::Start(start - 1))?;
            reader.read_exact(&mut prev)?;
            reader.seek(SeekFrom::Start(start))?;
            if prev[0] != b'\n' {
                let mut discard = String::new();
                let n = reader.read_line(&mut discard)?;
                if n == 0 {
                    return Ok((
                        0,
                        RunAccumulators::new(
                            32,
                            self.hll_precision,
                            self.enable_top_urls,
                            self.enable_top_hosts,
                            self.enable_top_refs,
                        ),
                    ));
                }
                pos += n as u64;
            }
        }

        let mut hourly: HourlyMap = AHashMap::with_capacity(32);
        let mut top_urls: TopUrlsByHits =
            AHashMap::with_capacity(if self.enable_top_urls { 32 } else { 0 });
        let mut top_urls_bw: TopUrlsByBandwidth =
            AHashMap::with_capacity(if self.enable_top_urls { 32 } else { 0 });
        let mut top_hosts: TopHostsByHits =
            AHashMap::with_capacity(if self.enable_top_hosts { 32 } else { 0 });
        let mut top_hosts_bw: TopHostsByBandwidth =
            AHashMap::with_capacity(if self.enable_top_hosts { 32 } else { 0 });
        let mut top_refs: PeriodCountMap =
            AHashMap::with_capacity(if self.enable_top_refs { 32 } else { 0 });
        let mut top_agents: PeriodCountMap = AHashMap::with_capacity(32);
        let mut top_countries: CountryHitsMap = AHashMap::with_capacity(32);
        let mut status_codes: StatusHitsMap = AHashMap::with_capacity(32);
        let mut hll_site_counts: AHashMap<Arc<str>, HyperLogLog> = AHashMap::with_capacity(32);
        let mut hll_all_time = Some(HyperLogLog::new(self.hll_precision));
        let mut method_counts = crate::method_proto::MethodCountsMap::with_capacity(32);
        let mut proto_counts = crate::method_proto::ProtoCountsMap::with_capacity(32);

        let mut lines_processed = 0u64;
        let mut line = String::new();

        while pos < end {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            pos += n as u64;

            if let Some(entry) = parser::parse_line(&line) {
                self.aggregate_entry_with_hll_split(
                    entry,
                    &mut hourly,
                    &mut top_urls,
                    &mut top_urls_bw,
                    &mut top_hosts,
                    &mut top_hosts_bw,
                    &mut top_refs,
                    &mut top_agents,
                    &mut top_countries,
                    &mut status_codes,
                    &mut hll_site_counts,
                    hll_all_time.as_mut(),
                    &mut method_counts,
                    &mut proto_counts,
                );
                lines_processed += 1;
            }

            if pos >= end {
                break;
            }
        }

        let run_acc = RunAccumulators {
            hourly,
            top_urls,
            top_urls_bw,
            top_hosts,
            top_hosts_bw,
            top_refs,
            top_agents,
            top_countries,
            status_codes,
            hll_site_counts,
            hll_all_time,
            method_counts,
            proto_counts,
        };

        Ok((lines_processed, run_acc))
    }
}
