//! Benchmark hook: print, as JSON, the exact prompts `scan --prescreen
//! cheap-model` would send for a repo's top audit units. No model calls.
//! The output CONTAINS SOURCE EXCERPTS (up to 60 lines per unit): keep it
//! local. Used by `benchmarks/ranking/run.py` (prescreen arm).
//!
//! `cargo run -q -p vettalon --example prescreen_prompts -- <repo_dir> [pool]`
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: prescreen_prompts <repo_dir> [pool]");
        std::process::exit(2);
    };
    let pool = match args.next().map(|p| p.parse::<usize>()) {
        None => vettalon::audit::prescreen::DEFAULT_POOL,
        Some(Ok(p)) if (1..=vettalon::audit::prescreen::MAX_POOL).contains(&p) => p,
        Some(_) => {
            eprintln!(
                "prescreen_prompts: pool must be 1-{}",
                vettalon::audit::prescreen::MAX_POOL
            );
            std::process::exit(2);
        }
    };
    let root = match std::fs::canonicalize(PathBuf::from(&dir)) {
        Ok(p) if p.is_dir() => p,
        _ => {
            eprintln!("prescreen_prompts: not a directory: {dir}");
            std::process::exit(2);
        }
    };
    let dump = vettalon::audit::prescreen::dump_prompts(&root, pool).await;
    match serde_json::to_string_pretty(&dump) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("prescreen_prompts: serialize failed: {e}");
            std::process::exit(1);
        }
    }
}
