use super::*;

impl Database {
    pub fn vacuum(&mut self) -> Result<()> {
        self.conn
            .execute_batch("VACUUM;")
            .context("Failed to VACUUM database")?;
        Ok(())
    }

    pub fn get_last_log_ts(&self) -> Result<i64> {
        Ok(self
            .get_meta("last_log_ts")?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0))
    }

    pub fn set_last_log_ts(&mut self, ts: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('last_log_ts', ?1)
             ON CONFLICT (key) DO UPDATE SET value = MAX(CAST(value AS INTEGER), ?1)",
            params![ts],
        )?;
        Ok(())
    }
}
