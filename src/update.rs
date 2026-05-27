use anyhow::{bail, Result};
use std::io::IsTerminal;

const REPO_OWNER: &str = "celsworth";
const REPO_NAME: &str = "webstat";

pub fn run(check_only: bool) -> Result<()> {
    let target = self_update::get_target();
    let current = self_update::cargo_crate_version!();

    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()?
        .fetch()?;

    let latest = match releases.first() {
        Some(r) => r,
        None => bail!("no releases found on GitHub"),
    };

    if !self_update::version::bump_is_greater(current, &latest.version)? {
        println!("webstat v{} is already the latest release", current);
        return Ok(());
    }

    println!("Current: v{}  →  Latest: v{}", current, latest.version);

    if check_only {
        return Ok(());
    }

    if latest.asset_for(&target, None).is_none() {
        bail!("no release artifact available for target '{}'", target);
    }

    if !std::io::stdin().is_terminal() {
        println!("Not a terminal — skipping update. Run interactively to apply.");
        return Ok(());
    }

    {
        use std::io::Write;
        print!("Proceed with update? [y/N] ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !line.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let status = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name("webstat")
        .target(&target)
        .current_version(current)
        // release.version strips the 'v' prefix; CI zip dirs include it
        .bin_path_in_archive("webstat-v{{ version }}-{{ target }}/{{ bin }}")
        .show_output(false)
        .show_download_progress(true)
        .no_confirm(true)
        .build()?
        .update()?;

    match status {
        self_update::Status::UpToDate(v) => println!("Already up to date: v{}", v),
        self_update::Status::Updated(v) => println!("Updated to v{}", v),
    }

    Ok(())
}
