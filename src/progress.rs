//! Transfer progress on stderr: silent for fast transfers, a single
//! rewriting line once 250ms have elapsed — which catches both "big file"
//! and "small file, slow link" — cleared again on completion so the normal
//! success message stands alone.

use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

const SHOW_AFTER: Duration = Duration::from_millis(250);
const REDRAW_EVERY: Duration = Duration::from_millis(50);

pub struct Progress {
    label: String,
    total: u64,
    start: Instant,
    last_draw: Option<Instant>,
    enabled: bool,
}

impl Progress {
    pub fn new(label: &str, total: u64) -> Progress {
        let enabled = match std::env::var("BACKCHANNEL_PROGRESS").ok().as_deref() {
            Some("always") => true,
            Some("never") => false,
            _ => std::io::stderr().is_terminal(),
        };
        Progress {
            label: label.into(),
            total,
            start: Instant::now(),
            last_draw: None,
            enabled,
        }
    }

    pub fn update(&mut self, sent: u64) {
        if !self.enabled || self.start.elapsed() < SHOW_AFTER {
            return;
        }
        if let Some(t) = self.last_draw
            && t.elapsed() < REDRAW_EVERY && sent < self.total {
                return;
            }
        self.last_draw = Some(Instant::now());
        eprint!("\r{}", render(&self.label, sent, self.total, self.start.elapsed()));
        let _ = std::io::stderr().flush();
    }

    pub fn finish(&mut self) {
        if self.last_draw.is_some() {
            let width = render(&self.label, self.total, self.total, self.start.elapsed())
                .chars()
                .count();
            eprint!("\r{}\r", " ".repeat(width));
            let _ = std::io::stderr().flush();
        }
    }
}

fn render(label: &str, sent: u64, total: u64, elapsed: Duration) -> String {
    const CELLS: usize = 24;
    let frac = if total == 0 {
        1.0
    } else {
        (sent as f64 / total as f64).clamp(0.0, 1.0)
    };
    let filled = ((frac * CELLS as f64).round() as usize).min(CELLS);
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    let rate = mib(sent) / elapsed.as_secs_f64().max(0.001);
    format!(
        "{label}: [{}{}] {:3.0}% {:.1}/{:.1} MiB ({rate:.1} MiB/s)",
        "#".repeat(filled),
        "-".repeat(CELLS - filled),
        frac * 100.0,
        mib(sent),
        mib(total),
    )
}

pub struct TransferStats {
    pub bytes: u64,
    pub elapsed: Duration,
}

impl TransferStats {
    /// "14.6 MiB in 2.8s, 5.3 MiB/s" — None for sub-threshold blips, where
    /// timing would be noise.
    pub fn summary(&self) -> Option<String> {
        if self.elapsed < SHOW_AFTER {
            return None;
        }
        let mib = self.bytes as f64 / (1024.0 * 1024.0);
        let secs = self.elapsed.as_secs_f64();
        Some(format!(
            "{mib:.1} MiB in {secs:.1}s, {:.1} MiB/s",
            mib / secs.max(0.001)
        ))
    }
}

/// Frame write in chunks with per-chunk progress. Socket-buffer
/// backpressure means written-bytes closely track actual transfer.
pub fn write_frame_with_progress(
    w: &mut impl Write,
    payload: &[u8],
    label: &str,
) -> std::io::Result<TransferStats> {
    let start = Instant::now();
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    let mut progress = Progress::new(label, payload.len() as u64);
    let mut sent = 0u64;
    for chunk in payload.chunks(128 * 1024) {
        w.write_all(chunk)?;
        sent += chunk.len() as u64;
        progress.update(sent);
    }
    w.flush()?;
    progress.finish();
    Ok(TransferStats {
        bytes: payload.len() as u64,
        elapsed: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::render;
    use std::time::Duration;

    #[test]
    fn renders_partial_and_complete() {
        let line = render("a.tif", 5 * 1024 * 1024, 10 * 1024 * 1024, Duration::from_secs(1));
        assert!(line.contains("a.tif:"), "{line}");
        assert!(line.contains(" 50% 5.0/10.0 MiB"), "{line}");
        assert!(line.contains("(5.0 MiB/s)"), "{line}");
        assert!(line.contains("############------------"), "{line}");

        let done = render("a.tif", 10, 10, Duration::from_secs(1));
        assert!(done.contains("100%"), "{done}");
        assert!(done.contains("########################"), "{done}");
    }

    #[test]
    fn zero_total_does_not_divide_by_zero() {
        let line = render("x", 0, 0, Duration::from_millis(1));
        assert!(line.contains("100%"), "{line}");
    }

    #[test]
    fn stats_summary_thresholds() {
        use super::TransferStats;
        let fast = TransferStats {
            bytes: 4096,
            elapsed: Duration::from_millis(30),
        };
        assert!(fast.summary().is_none());

        let slow = TransferStats {
            bytes: 15 * 1024 * 1024,
            elapsed: Duration::from_secs(3),
        };
        assert_eq!(slow.summary().unwrap(), "15.0 MiB in 3.0s, 5.0 MiB/s");
    }
}
