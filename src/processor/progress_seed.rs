use super::*;

pub(super) struct SeededProgress {
    pub(super) bytes_done: u64,
    pub(super) gz_comp_done: u64,
    pub(super) gz_decoded_done: u64,
}

impl Processor {
    pub(super) fn compute_seeded_progress(
        &self,
        files: &[String],
        current_inodes: &[u64],
        raw_file_sizes: &[u64],
        is_compressed_vec: &[bool],
    ) -> Result<SeededProgress> {
        let mut seeded_bytes_done = 0u64;
        let mut seeded_gz_comp_done = 0u64;
        let mut seeded_gz_decoded_done = 0u64;

        for idx in 0..files.len() {
            let filepath = &files[idx];
            let current_inode = current_inodes[idx];
            if current_inode == 0 {
                continue;
            }

            let Some(state) = self.db.get_parse_state(filepath)? else {
                continue;
            };
            if state.inode != current_inode {
                continue;
            }

            if is_compressed_vec[idx] {
                seeded_bytes_done = seeded_bytes_done.saturating_add(state.uncompressed_offset);
                if state.completed && state.compressed_offset >= raw_file_sizes[idx] {
                    seeded_gz_comp_done = seeded_gz_comp_done.saturating_add(raw_file_sizes[idx]);
                    seeded_gz_decoded_done =
                        seeded_gz_decoded_done.saturating_add(state.uncompressed_offset);
                }
            } else {
                let plain_done = state.uncompressed_offset.min(raw_file_sizes[idx]);
                seeded_bytes_done = seeded_bytes_done.saturating_add(plain_done);
            }
        }

        Ok(SeededProgress {
            bytes_done: seeded_bytes_done,
            gz_comp_done: seeded_gz_comp_done,
            gz_decoded_done: seeded_gz_decoded_done,
        })
    }
}
