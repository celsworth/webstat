use super::*;

impl Database {
    pub fn vacuum(&mut self) -> Result<()> {
        self.conn
            .execute_batch("VACUUM;")
            .context("Failed to VACUUM database")?;
        Ok(())
    }
}
