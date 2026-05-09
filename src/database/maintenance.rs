use super::*;

impl Database {
    pub(super) fn upsert_site_count_hlls(
        tx: &rusqlite::Transaction<'_>,
        hll_site_counts: &AHashMap<Arc<str>, HyperLogLog>,
        hll_all_time: Option<&HyperLogLog>,
    ) -> Result<()> {
        let mut select_stmt =
            tx.prepare_cached("SELECT sketch FROM site_counts_hll WHERE scope = ?1")?;
        let mut upsert_stmt = tx.prepare_cached(
            "INSERT INTO site_counts_hll (scope, estimate, sketch)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (scope) DO UPDATE SET
               estimate = excluded.estimate,
               sketch = excluded.sketch",
        )?;

        for (scope, incoming) in hll_site_counts {
            let merged = Self::merge_hll_blob(&mut select_stmt, scope.as_ref(), incoming)?;
            upsert_stmt.execute(params![
                scope.as_ref(),
                merged.estimate() as i64,
                merged.to_bytes()
            ])?;
        }

        if let Some(incoming) = hll_all_time {
            let merged = Self::merge_hll_blob(&mut select_stmt, "__all__", incoming)?;
            upsert_stmt.execute(params![
                "__all__",
                merged.estimate() as i64,
                merged.to_bytes()
            ])?;
        }

        Ok(())
    }

    fn merge_hll_blob(
        select_stmt: &mut rusqlite::CachedStatement<'_>,
        scope: &str,
        incoming: &HyperLogLog,
    ) -> Result<HyperLogLog> {
        let mut merged = incoming.clone();
        let existing = select_stmt.query_row(params![scope], |row| row.get::<_, Vec<u8>>(0));
        match existing {
            Ok(blob) => {
                if let Some(existing_hll) = HyperLogLog::from_bytes(&blob) {
                    merged.merge(&existing_hll);
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {}
            Err(err) => return Err(err.into()),
        }
        Ok(merged)
    }

    // ── Top-table trim ───────────────────────────────────────────────────────

    /// Remove rows ranked outside `top_n` for older periods and outside
    /// `topn_k` for current periods.
    ///
    /// Unique site counts at all granularities (daily, monthly, yearly, all-time)
    /// are tracked via HyperLogLog, so only month-level top_hosts rows are retained.
    pub fn trim_top_tables(
        &mut self,
        top_n: usize,
        topn_k: usize,
        keep_current: bool,
        vacuum_after_prune: bool,
    ) -> Result<()> {
        if top_n == 0 {
            return Ok(());
        }

        let current_limit = topn_k.max(1);

        let tx = self.conn.transaction()?;

        if keep_current {
            Self::trim_table_two_pass(&tx, "top_urls_hits", "hits", top_n, current_limit)?;
        } else {
            Self::trim_table(&tx, "top_urls_hits", "hits", top_n, false, None)?;
        }

        for table in [
            "top_refs",
            "top_agents",
            "top_countries",
            "top_hosts",
            "top_hosts_hits",
        ] {
            Self::trim_table(&tx, table, "hits", top_n, keep_current, None)?;
        }

        if keep_current {
            Self::trim_table_two_pass(
                &tx,
                "top_urls_bandwidth",
                "bandwidth",
                top_n,
                current_limit,
            )?;
        } else {
            Self::trim_table(&tx, "top_urls_bandwidth", "bandwidth", top_n, false, None)?;
        }

        Self::trim_table(
            &tx,
            "top_hosts_bandwidth",
            "bandwidth",
            top_n,
            keep_current,
            None,
        )?;

        tx.commit().context("Failed to commit trim transaction")?;

        if vacuum_after_prune {
            // Reclaim free pages created by pruning so DB size does not grow
            // without bound over long-running incremental imports.
            self.conn
                .execute_batch("VACUUM;")
                .context("Failed to VACUUM database after pruning")?;
        }

        Ok(())
    }

    fn trim_table(
        tx: &rusqlite::Transaction<'_>,
        table: &str,
        order_col: &str,
        top_n: usize,
        keep_current: bool,
        extra_where: Option<&str>,
    ) -> Result<()> {
        let mut conditions = Vec::new();

        if keep_current {
            conditions.push(format!(
                "period != COALESCE((SELECT MAX(period) FROM {table} WHERE LENGTH(period) = 7), '')"
            ));
            conditions.push(format!(
                "period != COALESCE((SELECT MAX(period) FROM {table} WHERE LENGTH(period) = 4), '')"
            ));
        }

        if let Some(extra) = extra_where {
            conditions.push(extra.to_string());
        }

        let where_sql = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "DELETE FROM {table}
             WHERE rowid IN (
               SELECT rowid FROM (
                 SELECT rowid,
                   ROW_NUMBER() OVER (PARTITION BY period ORDER BY {order_col} DESC, hits DESC) AS rn
                 FROM {table}
                 {where_sql}
               ) ranked
               WHERE rn > ?1
             )"
        );

        tx.execute(&sql, params![top_n as i64])?;
        Ok(())
    }

    fn trim_table_two_pass(
        tx: &rusqlite::Transaction<'_>,
        table: &str,
        order_col: &str,
        top_n: usize,
        topn_k: usize,
    ) -> Result<()> {
        let sql_old = format!(
                        "DELETE FROM {table}
                         WHERE rowid IN (
                             SELECT rowid FROM (
                                 SELECT rowid,
                                     ROW_NUMBER() OVER (PARTITION BY period ORDER BY {order_col} DESC, hits DESC) AS rn
                                 FROM {table}
                                 WHERE period != COALESCE((SELECT MAX(period) FROM {table} WHERE LENGTH(period) = 7), '')
                                     AND period != COALESCE((SELECT MAX(period) FROM {table} WHERE LENGTH(period) = 4), '')
                             ) ranked
                             WHERE rn > ?1
                         )"
                );
        tx.execute(&sql_old, params![top_n as i64])?;

        let sql_current = format!(
                        "DELETE FROM {table}
                         WHERE rowid IN (
                             SELECT rowid FROM (
                                 SELECT rowid,
                                     ROW_NUMBER() OVER (PARTITION BY period ORDER BY {order_col} DESC, hits DESC) AS rn
                                 FROM {table}
                                 WHERE period = COALESCE((SELECT MAX(period) FROM {table} WHERE LENGTH(period) = 7), '')
                                        OR period = COALESCE((SELECT MAX(period) FROM {table} WHERE LENGTH(period) = 4), '')
                             ) ranked
                             WHERE rn > ?1
                         )"
                );
        tx.execute(&sql_current, params![topn_k as i64])?;

        Ok(())
    }
}
