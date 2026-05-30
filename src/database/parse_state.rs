// Parse state persistence: load and save per-file ParseState rows that drive resume decisions.

use rusqlite::OptionalExtension;

use super::*;

macro_rules! ps_cols {
    () => {
        "filepath, inode, compressed_size, uncompressed_size, \
         compressed_head_fingerprint, uncompressed_head_fingerprint, \
         compressed_offset, uncompressed_offset, mtime_ns, completed, \
         earliest_ts, latest_ts, skip_before_ts"
    };
}

/// Columns selected when loading a ParseState from either table.
const PARSE_STATE_COLS: &str = ps_cols!();

/// The same columns projected from both parse_state and parse_state_archive,
/// used in UNION ALL queries.
const PARSE_STATE_UNION: &str = concat!(
    "SELECT ", ps_cols!(), " FROM parse_state \
     UNION ALL \
     SELECT ", ps_cols!(), " FROM parse_state_archive"
);

impl Database {
    // ── Parse state ───────────────────────────────────────────────────────────

    fn row_to_parse_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<ParseState> {
        Ok(ParseState {
            filepath: row.get::<_, String>(0)?,
            inode: row.get::<_, i64>(1)? as u64,
            compressed_size: row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
            uncompressed_size: row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
            compressed_head_fingerprint: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
            uncompressed_head_fingerprint: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            compressed_offset: row.get::<_, Option<i64>>(6)?.unwrap_or(0) as u64,
            uncompressed_offset: row.get::<_, Option<i64>>(7)?.unwrap_or(0) as u64,
            mtime_ns: row.get::<_, Option<i64>>(8)?.unwrap_or(0),
            completed: row.get::<_, Option<i64>>(9)?.unwrap_or(0) != 0,
            earliest_ts: row.get::<_, Option<i64>>(10)?,
            latest_ts: row.get::<_, Option<i64>>(11)?,
            skip_before_ts: row.get::<_, Option<i64>>(12)?,
        })
    }

    pub fn get_parse_state(&self, filepath: &str) -> Result<Option<ParseState>> {
        let sql = format!("SELECT {PARSE_STATE_COLS} FROM parse_state WHERE filepath = ?");
        let mut st = self.conn.prepare_cached(&sql)?;
        Ok(st
            .query_row(params![filepath], Self::row_to_parse_state)
            .optional()?)
    }

    pub fn get_parse_state_by_inode(&self, inode: u64) -> Result<Option<ParseState>> {
        let sql = format!("SELECT {PARSE_STATE_COLS} FROM parse_state WHERE inode = ? LIMIT 1");
        let mut st = self.conn.prepare_cached(&sql)?;
        if let Some(s) = st
            .query_row(params![inode as i64], Self::row_to_parse_state)
            .optional()?
        {
            return Ok(Some(s));
        }

        let sql_archive = format!(
            "SELECT {PARSE_STATE_COLS} FROM parse_state_archive \
             WHERE inode = ? ORDER BY completed DESC, uncompressed_offset DESC LIMIT 1"
        );
        let mut st_archive = self.conn.prepare_cached(&sql_archive)?;
        Ok(st_archive
            .query_row(params![inode as i64], Self::row_to_parse_state)
            .optional()?)
    }

    pub fn find_completed_by_uncompressed_identity(
        &self,
        head_fingerprint: u64,
        uncompressed_size: u64,
    ) -> Result<bool> {
        let sql = format!(
            "SELECT 1 FROM ({PARSE_STATE_UNION}) \
             WHERE uncompressed_head_fingerprint = ? \
               AND uncompressed_size = ? \
               AND completed = 1 \
             LIMIT 1"
        );
        let mut st = self.conn.prepare_cached(&sql)?;
        Ok(st
            .query_row(
                params![head_fingerprint as i64, uncompressed_size as i64],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Find a completed entry by compressed head fingerprint + compressed size.
    /// Returns the stored uncompressed_size so we can populate the new parse_state correctly.
    pub fn find_completed_by_compressed_identity(
        &self,
        head_fingerprint: u64,
        compressed_size: u64,
    ) -> Result<Option<u64>> {
        let sql = format!(
            "SELECT uncompressed_size FROM ({PARSE_STATE_UNION}) \
             WHERE compressed_head_fingerprint = ? \
               AND compressed_size = ? \
               AND completed = 1 \
             LIMIT 1"
        );
        let mut st = self.conn.prepare_cached(&sql)?;
        Ok(st
            .query_row(
                params![head_fingerprint as i64, compressed_size as i64],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|v| v as u64))
    }

    pub fn find_parse_state_by_uncompressed_head_fingerprint(
        &self,
        head_fingerprint: u64,
    ) -> Result<Option<ParseState>> {
        let sql = format!(
            "SELECT {PARSE_STATE_COLS} FROM ({PARSE_STATE_UNION}) \
             WHERE uncompressed_head_fingerprint = ? \
             ORDER BY completed DESC, uncompressed_offset DESC \
             LIMIT 1"
        );
        let mut st = self.conn.prepare_cached(&sql)?;
        Ok(st
            .query_row(params![head_fingerprint as i64], Self::row_to_parse_state)
            .optional()?)
    }

    pub fn find_parse_state_by_compressed_head_fingerprint(
        &self,
        head_fingerprint: u64,
    ) -> Result<Option<ParseState>> {
        let sql = format!(
            "SELECT {PARSE_STATE_COLS} FROM ({PARSE_STATE_UNION}) \
             WHERE compressed_head_fingerprint = ? \
             ORDER BY completed DESC, compressed_offset DESC \
             LIMIT 1"
        );
        let mut st = self.conn.prepare_cached(&sql)?;
        Ok(st
            .query_row(params![head_fingerprint as i64], Self::row_to_parse_state)
            .optional()?)
    }

    #[cfg(test)]
    pub fn set_parse_state(&self, state: &ParseState) -> Result<()> {
        self.conn.execute(
            "INSERT INTO parse_state \
             (filepath, inode, compressed_size, uncompressed_size, \
              compressed_head_fingerprint, uncompressed_head_fingerprint, \
              compressed_offset, uncompressed_offset, mtime_ns, completed, \
              earliest_ts, latest_ts, skip_before_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
             ON CONFLICT (filepath) DO UPDATE SET \
               inode = ?2, \
               compressed_size = ?3, \
               uncompressed_size = ?4, \
               compressed_head_fingerprint = ?5, \
               uncompressed_head_fingerprint = ?6, \
               compressed_offset = ?7, \
               uncompressed_offset = ?8, \
               mtime_ns = ?9, \
               completed = ?10, \
               earliest_ts = ?11, \
               latest_ts = ?12, \
               skip_before_ts = ?13",
            params![
                state.filepath,
                state.inode as i64,
                state.compressed_size as i64,
                state.uncompressed_size as i64,
                state.compressed_head_fingerprint.map(|f| f as i64),
                state.uncompressed_head_fingerprint.map(|f| f as i64),
                state.compressed_offset as i64,
                state.uncompressed_offset as i64,
                state.mtime_ns,
                state.completed as i64,
                state.earliest_ts,
                state.latest_ts,
                state.skip_before_ts,
            ],
        )?;
        Ok(())
    }
}
