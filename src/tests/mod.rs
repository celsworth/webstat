// Integration tests live here.  Each file in this module drives the full
// pipeline (log ingestion, aggregation, report generation) using real files on
// disk via TempDir.  Unit tests for individual modules remain co-located with
// the code they test.

mod pipeline;
mod reports;
