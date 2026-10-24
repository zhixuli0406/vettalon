//! Measure fresh-container execution with repeated vs operation-scoped preflight.
//! This is an execution-overhead benchmark, not a model or exploit benchmark.
//! Nothing runs on the host except the trusted Docker CLI; no images are pulled.

use std::time::{Duration, Instant};

use serde::Serialize;
use vettalon::sandbox::{DEFAULT_POC_IMAGE, DockerSandbox, SandboxSession};

const SCRIPT: &str = r#"import os, socket
assert os.getuid() == 65534
try:
    open('/vtl-root-write-probe', 'w')
except OSError:
    pass
else:
    raise AssertionError('root filesystem was writable')
s = socket.socket()
s.settimeout(0.2)
assert s.connect_ex(('192.0.2.1', 443)) != 0
s.close()
print('VTL_BENCH_COMPLETE')
"#;

#[derive(Serialize)]
struct Sample {
    index: usize,
    mode: &'static str,
    phases: usize,
    preflight_ms: f64,
    execution_ms: f64,
    total_ms: f64,
    image_id: Option<String>,
    error: Option<String>,
}

async fn sample(image: &str, mode: &'static str, phases: usize, index: usize) -> Sample {
    let session = SandboxSession::new();
    let mut grouped = None;
    let started = Instant::now();
    let mut row = Sample {
        index,
        mode,
        phases,
        preflight_ms: 0.0,
        execution_ms: 0.0,
        total_ms: 0.0,
        image_id: None,
        error: None,
    };
    for phase in 0..phases {
        let before = Instant::now();
        let sandbox = match mode {
            "session" => session.sandbox(image).await,
            "finding_grouped_preflight" => {
                if phase % 3 == 0 {
                    grouped = match DockerSandbox::detect(image).await {
                        Ok(sandbox) => Some(sandbox),
                        Err(error) => {
                            row.preflight_ms += before.elapsed().as_secs_f64() * 1000.0;
                            row.error = Some(error);
                            break;
                        }
                    };
                }
                Ok(grouped
                    .as_ref()
                    .expect("group starts with preflight")
                    .clone())
            }
            _ => DockerSandbox::detect(image).await,
        };
        row.preflight_ms += before.elapsed().as_secs_f64() * 1000.0;
        let sandbox = match sandbox {
            Ok(sandbox) => sandbox,
            Err(error) => {
                row.error = Some(error);
                break;
            }
        };
        row.image_id = Some(sandbox.image.clone());
        let before = Instant::now();
        let result = sandbox
            .run_script(SCRIPT, "python", Duration::from_secs(10))
            .await;
        row.execution_ms += before.elapsed().as_secs_f64() * 1000.0;
        match result {
            Ok((0, output)) if output.trim() == "VTL_BENCH_COMPLETE" => {}
            Ok((code, _)) => {
                row.error = Some(format!("incomplete probe, exit={code}"));
                break;
            }
            Err(error) => {
                row.error = Some(error);
                break;
            }
        }
    }
    row.total_ms = started.elapsed().as_secs_f64() * 1000.0;
    row
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 4 {
        eprintln!(
            "usage: poc_sandbox_bench [local-image] [samples-per-workload:1..50] [new-output.json]"
        );
        std::process::exit(2);
    }
    let image = args.get(1).map_or(DEFAULT_POC_IMAGE, String::as_str);
    let samples = match args.get(2).map(|n| n.parse::<usize>()) {
        None => 5,
        Some(Ok(n @ 1..=50)) => n,
        _ => {
            eprintln!("samples must be an integer in 1..=50");
            std::process::exit(2);
        }
    };
    let mut rows = Vec::new();
    // Alternate ordering to avoid giving either mode all early/cold samples.
    // Every sample and phase still creates a fresh, single-use container.
    for phases in [1, 3, 9] {
        for index in 0..samples {
            let order = match index % 3 {
                0 => ["fresh_preflight", "finding_grouped_preflight", "session"],
                1 => ["finding_grouped_preflight", "session", "fresh_preflight"],
                _ => ["session", "fresh_preflight", "finding_grouped_preflight"],
            };
            for mode in order {
                rows.push(sample(image, mode, phases, index).await);
            }
        }
    }
    let complete = rows.iter().all(|row| row.error.is_none());
    let encoded = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "vettalon.sandbox-overhead/2",
        "captured_at": chrono::Utc::now().to_rfc3339(),
        "requested_image": image,
        "complete": complete,
        "samples_per_workload": samples,
        "scope": "fresh containers; equal current isolation and cleanup; execution overhead only",
        "comparison": "per-phase vs per-finding (3 phases) vs operation-scoped preflight in this source snapshot; not a released binary, full scan, or SPACE comparison",
        "rows": rows,
    }))
    .expect("serializable benchmark rows");
    if let Some(path) = args.get(3) {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(path).unwrap_or_else(|error| {
            eprintln!("cannot create new benchmark receipt {path}: {error}");
            std::process::exit(2);
        });
        file.write_all(&encoded).unwrap_or_else(|error| {
            eprintln!("cannot write benchmark receipt {path}: {error}");
            std::process::exit(2);
        });
        eprintln!("wrote {path}");
    } else {
        println!("{}", String::from_utf8(encoded).expect("JSON is UTF-8"));
    }
    if !complete {
        std::process::exit(1);
    }
}
