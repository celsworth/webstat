use super::*;

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
        })
    }

    pub fn get_parse_state(&self, filepath: &str) -> Result<Option<ParseState>> {
        let mut st = self.conn.prepare_cached(
            "SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
             FROM parse_state WHERE filepath = ?",
        )?;
        let mut rows = st.query(params![filepath])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(Self::row_to_parse_state(row)?)),
        }
    }

    pub fn get_parse_state_by_inode(&self, inode: u64) -> Result<Option<ParseState>> {
        let mut st = self.conn.prepare_cached(
            "SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
             FROM parse_state WHERE inode = ? LIMIT 1",
        )?;
        let mut rows = st.query(params![inode as i64])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(Self::row_to_parse_state(row)?));
        }

        let mut st_archive = self.conn.prepare_cached(
            "SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
             FROM parse_state_archive WHERE inode = ? ORDER BY completed DESC, uncompressed_offset DESC LIMIT 1",
        )?;
        let mut rows = st_archive.query(params![inode as i64])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(Self::row_to_parse_state(row)?)),
        }
    }

    pub fn find_completed_by_uncompressed_identity(
        &self,
        head_fingerprint: u64,
        uncompressed_size: u64,
    ) -> Result<bool> {
        let mut st = self.conn.prepare_cached(
            "SELECT 1
             FROM (
               SELECT uncompressed_head_fingerprint, uncompressed_size, completed FROM parse_state
               UNION ALL
               SELECT uncompressed_head_fingerprint, uncompressed_size, completed FROM parse_state_archive
             )
             WHERE uncompressed_head_fingerprint = ? AND uncompressed_size = ? AND completed = 1
             LIMIT 1",
        )?;
        let mut rows = st.query(params![head_fingerprint as i64, uncompressed_size as i64])?;
        Ok(rows.next()?.is_some())
    }

    /// Find a completed entry by compressed head fingerprint + compressed size.
    /// Returns the stored uncompressed_size so we can populate the new parse_state correctly.
    pub fn find_completed_by_compressed_identity(
        &self,
        head_fingerprint: u64,
        compressed_size: u64,
    ) -> Result<Option<u64>> {
        let mut st = self.conn.prepare_cached(
            "SELECT uncompressed_size
             FROM (
               SELECT compressed_head_fingerprint, compressed_size, uncompressed_size, completed FROM parse_state
               UNION ALL
               SELECT compressed_head_fingerprint, compressed_size, uncompressed_size, completed FROM parse_state_archive
             )
             WHERE compressed_head_fingerprint = ? AND compressed_size = ? AND completed = 1
             LIMIT 1",
        )?;
        let mut rows = st.query(params![head_fingerprint as i64, compressed_size as i64])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get::<_, i64>(0)? as u64))
        } else {
            Ok(None)
        }
    }

    /// Find a completed plain-file entry by uncompressed head fingerprint.
    /// Only matches entries where `compressed_head_fingerprint IS NULL` (plain files),
    /// so gzip files with a shared uncompressed prefix are not false-positively skipped.
    pub fn find_completed_by_uncompressed_head_only(
        &self,
        head_fingerprint: u64,
    ) -> Result<Option<u64>> {
        let mut st = self.conn.prepare_cached(
            "SELECT uncompressed_size
             FROM (
               SELECT uncompressed_head_fingerprint, uncompressed_size, completed, compressed_head_fingerprint FROM parse_state
               UNION ALL
               SELECT uncompressed_head_fingerprint, uncompressed_size, completed, compressed_head_fingerprint FROM parse_state_archive
             )
             WHERE uncompressed_head_fingerprint = ? AND completed = 1 AND compressed_head_fingerprint IS NULL
             LIMIT 1",
        )?;
        let mut rows = st.query(params![head_fingerprint as i64])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get::<_, i64>(0)? as u64))
        } else {
            Ok(None)
        }
    }

    pub fn find_parse_state_by_uncompressed_head_fingerprint(
        &self,
        head_fingerprint: u64,
    ) -> Result<Option<ParseState>> {
        let mut st = self.conn.prepare_cached(
                        "SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
             FROM (
                            SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
               FROM parse_state
               WHERE uncompressed_head_fingerprint = ?
               UNION ALL
                            SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
               FROM parse_state_archive
               WHERE uncompressed_head_fingerprint = ?
             )
             ORDER BY completed DESC, uncompressed_offset DESC
             LIMIT 1",
        )?;
        let mut rows = st.query(params![head_fingerprint as i64, head_fingerprint as i64])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(Self::row_to_parse_state(row)?)),
        }
    }

    pub fn find_parse_state_by_compressed_head_fingerprint(
        &self,
        head_fingerprint: u64,
    ) -> Result<Option<ParseState>> {
        let mut st = self.conn.prepare_cached(
                        "SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
             FROM (
                             SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
               FROM parse_state
               WHERE compressed_head_fingerprint = ?
               UNION ALL
                             SELECT filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed
               FROM parse_state_archive
               WHERE compressed_head_fingerprint = ?
             )
             ORDER BY completed DESC, compressed_offset DESC
             LIMIT 1",
        )?;
        let mut rows = st.query(params![head_fingerprint as i64, head_fingerprint as i64])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(Self::row_to_parse_state(row)?)),
        }
    }

    #[cfg(test)]
    pub fn set_parse_state(
        &self,
        filepath: &str,
        inode: u64,
        compressed_size: u64,
        uncompressed_size: u64,
        compressed_head_fingerprint: Option<u64>,
        uncompressed_head_fingerprint: Option<u64>,
        compressed_offset: u64,
        uncompressed_offset: u64,
        mtime_ns: i64,
        completed: bool,
    ) -> Result<()> {
        self.conn.execute(
                        "INSERT INTO parse_state (filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT (filepath) DO UPDATE SET
               inode = ?2,
               compressed_size = ?3,
               uncompressed_size = ?4,
               compressed_head_fingerprint = ?5,
               uncompressed_head_fingerprint = ?6,
               compressed_offset = ?7,
               uncompressed_offset = ?8,
               mtime_ns = ?9,
               completed = ?10",
            params![
                filepath,
                inode as i64,
                compressed_size as i64,
                uncompressed_size as i64,
                compressed_head_fingerprint.map(|f| f as i64),
                uncompressed_head_fingerprint.map(|f| f as i64),
                compressed_offset as i64,
                uncompressed_offset as i64,
                mtime_ns,
                completed as i64,
            ],
        )?;
        Ok(())
    }
}
