use std::str::FromStr;

use anyhow::Context;
use chrono::Utc;
use cron::Schedule;

use crate::config::{ScannerConfig, normalize_cron};
use crate::scan;

#[derive(Debug)]
pub struct Scheduler {
    schedule: Schedule,
}

impl Scheduler {
    pub fn new(cron_expr: &str) -> anyhow::Result<Scheduler> {
        let normalized = normalize_cron(cron_expr);
        let schedule =
            Schedule::from_str(&normalized).context(format!("invalid cron expression: {cron_expr}"))?;
        Ok(Scheduler { schedule })
    }

    /// Returns the next upcoming occurrence after the current time.
    pub fn next_tick(&self) -> chrono::DateTime<Utc> {
        self.schedule
            .upcoming(Utc)
            .next()
            .expect("cron schedule has no upcoming occurrence")
    }
}

/// Run the scan loop. If `once` is true, run one cycle and return.
/// Otherwise, create a Scheduler and loop on the cron schedule.
pub async fn run_loop(config: &ScannerConfig, once: bool) -> anyhow::Result<()> {
    let mut cycle: u64 = 0;

    if once {
        cycle += 1;
        scan::run_scan_cycle(&config.repos, cycle);
        return Ok(());
    }

    let scheduler = Scheduler::new(&config.scanner.schedule)?;

    loop {
        let next = scheduler.next_tick();
        let now = Utc::now();
        let wait = (next - now)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        tracing::info!(next = %next, wait_secs = wait.as_secs(), "Waiting for next scheduled run");
        tokio::time::sleep(wait).await;

        cycle += 1;
        scan::run_scan_cycle(&config.repos, cycle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn valid_cron_five_field() {
        let s = Scheduler::new("*/5 * * * *").unwrap();
        let next = s.next_tick();
        assert!(next > Utc::now());
    }

    #[test]
    fn valid_cron_six_field() {
        let s = Scheduler::new("0 */5 * * * *").unwrap();
        let next = s.next_tick();
        assert!(next > Utc::now());
    }

    #[test]
    fn invalid_expression_errors() {
        let err = Scheduler::new("not a cron").unwrap_err();
        assert!(
            err.to_string().contains("invalid cron"),
            "expected cron error, got: {err}"
        );
    }

    #[test]
    fn next_tick_is_in_the_future() {
        let s = Scheduler::new("0 * * * *").unwrap();
        let next = s.next_tick();
        assert!(next > Utc::now());
    }

    #[test]
    fn next_tick_within_expected_range() {
        // "0 * * * *" = top of every hour; next tick should be within 1 hour
        let s = Scheduler::new("0 * * * *").unwrap();
        let next = s.next_tick();
        let now = Utc::now();
        let diff = next - now;
        assert!(diff.num_seconds() > 0);
        assert!(diff.num_seconds() <= 3600);
    }

    #[test]
    fn every_minute_next_tick_within_one_minute() {
        let s = Scheduler::new("* * * * *").unwrap();
        let next = s.next_tick();
        let now = Utc::now();
        let diff = next - now;
        assert!(diff.num_seconds() > 0);
        assert!(diff.num_seconds() <= 60);
    }
}
