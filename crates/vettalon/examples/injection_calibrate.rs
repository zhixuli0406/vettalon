//! Calibration helper: score every text file under a directory with the
//! injection guard and print the score distribution and the top hits.
//! `cargo run --example injection_calibrate -- <dir>`
use vettalon::guard::input_guard::scan_input;

fn main() {
    let dir = std::env::args().nth(1).expect("dir");
    let mut scores: Vec<(u32, String, Vec<String>)> = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(&dir)];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.')
                || ["target", "node_modules", "vendor", "dist", "build"].contains(&name.as_str())
            {
                continue;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
                if ![
                    "rs", "py", "ts", "tsx", "js", "go", "java", "php", "rb", "swift", "kt", "md",
                    "toml", "yaml", "yml", "json",
                ]
                .contains(&ext)
                {
                    continue;
                }
                let Ok(t) = std::fs::read_to_string(&p) else {
                    continue;
                };
                let t = &t[..t.len().min(256 * 1024)];
                let t = t.get(..).unwrap_or("");
                let r = scan_input(t, 60);
                scores.push((r.risk_score, p.display().to_string(), r.matched_rules));
            }
        }
    }
    let n = scores.len();
    for th in [20, 30, 40, 60] {
        let c = scores.iter().filter(|s| s.0 >= th).count();
        println!(
            "score>={th}: {c}/{n} ({:.1}%)",
            100.0 * c as f64 / n.max(1) as f64
        );
    }
    scores.sort_by_key(|x| std::cmp::Reverse(x.0));
    for (s, p, r) in scores.iter().take(12) {
        println!("{s:>3} {p} {r:?}");
    }
}
