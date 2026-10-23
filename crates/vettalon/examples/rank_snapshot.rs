//! Dev/benchmark hook: print how a deep scan would rank and page a repo's
//! modules, with the metadata features behind the ranking, as JSON. No model
//! calls, no file contents. Used by the module-ranking benchmark (not in the
//! public repo).
//!
//! `cargo run -q -p vettalon --example rank_snapshot -- <repo_dir>`
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: rank_snapshot <repo_dir>");
        std::process::exit(2);
    };
    let root = match std::fs::canonicalize(PathBuf::from(&dir)) {
        Ok(p) if p.is_dir() => p,
        _ => {
            eprintln!("rank_snapshot: not a directory: {dir}");
            std::process::exit(2);
        }
    };
    let snap = vettalon::audit::rank_snapshot::rank_snapshot(&root).await;
    match serde_json::to_string_pretty(&snap) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("rank_snapshot: serialize failed: {e}");
            std::process::exit(1);
        }
    }
}
