//! apd — a self-hostable, multi-instance AAuth Agent Provider daemon.
//!
//! Subcommands:
//!   apd serve [--config PATH]        run the HTTP server
//!   apd keygen [--keys PATH] [--rotate] [--prune-days N]
//!   apd enroll-token --config PATH [--ps URL] [--ttl SECS]
//!   apd example-config               print an example config to stdout
//!   apd version

mod app;
mod audit;
mod config;
mod enrollment;
mod handlers;
mod httpc;
mod issue;
mod jwks_cache;
mod keys;
mod problem;
mod records;
mod reqctx;
mod router;
mod storage;

#[cfg(test)]
mod tests;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use app::App;
use config::Config;
use keys::KeySet;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let result = match cmd {
        "serve" => run_serve(&args),
        "keygen" => run_keygen(&args),
        "enroll-token" => run_enroll_token(&args),
        "example-config" => {
            if has_flag(&args, "--federated") {
                print!("{}", config::EXAMPLE_CONFIG_FEDERATED);
            } else {
                print!("{}", config::EXAMPLE_CONFIG);
            }
            Ok(())
        }
        "version" | "--version" | "-V" => {
            println!("apd {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            print_help();
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn print_help() {
    eprintln!(
        "apd {} — AAuth Agent Provider\n\n\
         USAGE:\n\
         \x20 apd serve [--config apd.json]\n\
         \x20 apd keygen [--keys apd-keys.json] [--rotate] [--prune-days N]\n\
         \x20 apd enroll-token --config apd.json [--ps https://ps.example] [--ttl 3600]\n\
         \x20 apd example-config [--federated] > apd.json\n\
         \x20 apd version\n\n\
         Environment overrides: APD_ISSUER, APD_LISTEN, APD_KEYS_FILE,\n\
         APD_ADMIN_TOKEN, APD_REDIS_ADDR.",
        env!("CARGO_PKG_VERSION")
    );
}

fn run_keygen(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--keys").unwrap_or("apd-keys.json");
    let rotate = has_flag(args, "--rotate");
    let prune = flag(args, "--prune-days")
        .map(|d| d.parse::<u64>().map(|days| days * 86400))
        .transpose()
        .map_err(|_| "invalid --prune-days")?;
    let msg = keys::keygen(path, rotate, prune)?;
    println!("{msg}");
    Ok(())
}

fn run_enroll_token(args: &[String]) -> Result<(), String> {
    let config_path = flag(args, "--config").unwrap_or("apd.json");
    let cfg = Config::load(config_path)?;
    let ps = flag(args, "--ps").map(|s| s.to_string());
    let ttl: u64 = flag(args, "--ttl")
        .map(|s| s.parse().map_err(|_| "invalid --ttl".to_string()))
        .transpose()?
        .unwrap_or(3600);
    if let Some(ps) = &ps {
        aauth_core::ident::validate_server_identifier(ps, cfg.insecure_dev_mode)
            .map_err(|_| "ps is not a valid server identifier".to_string())?;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        if cfg.storage.backend == "memory" {
            return Err(
                "enroll-token requires a persistent storage backend (file or redis); \
                        the memory backend is per-process. Configure file/redis storage, or use \
                        the admin API on a running server instead."
                    .to_string(),
            );
        }
        let store = storage::open(&cfg.storage)
            .await
            .map_err(|e| e.to_string())?;
        let token = aauth_core::rand_token(192);
        let record = records::EnrollTokenRecord {
            ps,
            label: Some("cli".into()),
            created_at: aauth_core::now_unix(),
        };
        store
            .put(
                &records::enroll_token_key(&token),
                &serde_json::to_vec(&record).unwrap(),
                Some(std::time::Duration::from_secs(ttl)),
            )
            .await
            .map_err(|e| e.to_string())?;
        println!("{token}");
        eprintln!("(single-use; expires in {ttl}s)");
        Ok(())
    })
}

fn run_serve(args: &[String]) -> Result<(), String> {
    let config_path = flag(args, "--config").unwrap_or("apd.json");
    let cfg = Config::load(config_path)?;
    let keys = KeySet::load(&cfg.keys_file)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(serve(cfg, keys))
}

async fn serve(cfg: Config, keys: KeySet) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listen = cfg.listen.clone();
    let issuer = cfg.issuer.clone();
    let store = storage::open(&cfg.storage)
        .await
        .map_err(|e| format!("storage init: {e}"))?;
    let admin_enabled = cfg.admin_token.is_some();
    let events_enabled = cfg.events.enabled;
    let backend = cfg.storage.backend.clone();
    let insecure = cfg.insecure_dev_mode;

    let app = App::new(cfg, keys, store)?;

    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|e| format!("cannot bind {listen}: {e}"))?;

    eprintln!("apd {} listening on {listen}", env!("CARGO_PKG_VERSION"));
    eprintln!("  issuer:   {issuer}");
    eprintln!("  storage:  {backend}");
    eprintln!(
        "  events:   {}",
        if events_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    eprintln!(
        "  admin:    {}",
        if admin_enabled { "enabled" } else { "disabled" }
    );
    if insecure {
        eprintln!("  WARNING:  insecure_dev_mode is ON — do not use in production");
    }

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, _peer) = match accept {
                    Ok(pair) => pair,
                    Err(e) => { eprintln!("accept error: {e}"); continue; }
                };
                stream.set_nodelay(true).ok();
                let app = app.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        let app = app.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(router::route(req, app).await)
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
            _ = &mut shutdown => {
                eprintln!("\nshutting down");
                break;
            }
        }
    }
    Ok(())
}
