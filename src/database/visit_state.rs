use super::*;

impl Database {
    pub fn load_visit_state(&self) -> Result<Vec<VisitStateUpdate>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ip_kind, ip_hi, ip_lo, ip_text, last_seen_ts FROM visit_state",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(VisitStateUpdate {
                key: VisitStateKey {
                    ip_kind: row.get::<_, i64>(0)? as u8,
                    ip_hi: row.get::<_, i64>(1)? as u64,
                    ip_lo: row.get::<_, i64>(2)? as u64,
                    ip_text: row.get::<_, String>(3)?,
                },
                last_seen_ts: row.get(4)?,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}
