//! Storage abstraction with three backends:
//!
//! - `memory` — in-process (dev, tests, single instance without persistence)
//! - `file`   — memory + crash-safe JSON snapshot (single host)
//! - `redis`  — minimal hand-rolled RESP2 client over TCP (multi-instance;
//!   no external client dependency)
//!
//! The interface is a small KV + list surface whose mutating operations map
//! onto atomic Redis primitives, so multi-instance correctness holds:
//! `put_if_absent` → SET NX, `take` → GETDEL, `incr` → INCR, lists →
//! RPUSH/LRANGE+DEL. See `research/02-agent-provider.md` §6.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub type SResult<T> = Result<T, StorageError>;

#[derive(Debug)]
pub struct StorageError(pub String);

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}
impl std::error::Error for StorageError {}

fn serr(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

pub enum Store {
    Memory(MemoryStore),
    File(FileStore),
    Redis(RedisStore),
}

impl Store {
    pub async fn get(&self, key: &str) -> SResult<Option<Vec<u8>>> {
        match self {
            Store::Memory(s) => Ok(s.inner.lock().await.get(key)),
            Store::File(s) => Ok(s.mem.inner.lock().await.get(key)),
            Store::Redis(s) => s.get(key).await,
        }
    }

    pub async fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> SResult<()> {
        match self {
            Store::Memory(s) => {
                s.inner.lock().await.put(key, value, ttl);
                Ok(())
            }
            Store::File(s) => {
                s.mem.inner.lock().await.put(key, value, ttl);
                s.persist().await
            }
            Store::Redis(s) => s.put(key, value, ttl).await,
        }
    }

    /// Atomic create-if-absent. Returns false if the key already existed.
    pub async fn put_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> SResult<bool> {
        match self {
            Store::Memory(s) => Ok(s.inner.lock().await.put_if_absent(key, value, ttl)),
            Store::File(s) => {
                let r = s.mem.inner.lock().await.put_if_absent(key, value, ttl);
                if r {
                    s.persist().await?;
                }
                Ok(r)
            }
            Store::Redis(s) => s.put_if_absent(key, value, ttl).await,
        }
    }

    pub async fn delete(&self, key: &str) -> SResult<bool> {
        match self {
            Store::Memory(s) => Ok(s.inner.lock().await.delete(key)),
            Store::File(s) => {
                let r = s.mem.inner.lock().await.delete(key);
                s.persist().await?;
                Ok(r)
            }
            Store::Redis(s) => s.delete(key).await,
        }
    }

    /// Atomic get-and-delete (single-use consumption).
    pub async fn take(&self, key: &str) -> SResult<Option<Vec<u8>>> {
        match self {
            Store::Memory(s) => Ok(s.inner.lock().await.take(key)),
            Store::File(s) => {
                let r = s.mem.inner.lock().await.take(key);
                s.persist().await?;
                Ok(r)
            }
            Store::Redis(s) => s.take(key).await,
        }
    }

    /// Atomic increment (creates at 1).
    pub async fn incr(&self, key: &str) -> SResult<i64> {
        match self {
            Store::Memory(s) => Ok(s.inner.lock().await.incr(key)),
            Store::File(s) => {
                let r = s.mem.inner.lock().await.incr(key);
                s.persist().await?;
                Ok(r)
            }
            Store::Redis(s) => s.incr(key).await,
        }
    }

    /// Append to a list, trimming to `max` newest entries.
    pub async fn list_push(&self, key: &str, value: &[u8], max: usize) -> SResult<()> {
        match self {
            Store::Memory(s) => {
                s.inner.lock().await.list_push(key, value, max);
                Ok(())
            }
            Store::File(s) => {
                s.mem.inner.lock().await.list_push(key, value, max);
                s.persist().await
            }
            Store::Redis(s) => s.list_push(key, value, max).await,
        }
    }

    /// Atomically read and clear a list.
    pub async fn list_drain(&self, key: &str) -> SResult<Vec<Vec<u8>>> {
        match self {
            Store::Memory(s) => Ok(s.inner.lock().await.list_drain(key)),
            Store::File(s) => {
                let r = s.mem.inner.lock().await.list_drain(key);
                if !r.is_empty() {
                    s.persist().await?;
                }
                Ok(r)
            }
            Store::Redis(s) => s.list_drain(key).await,
        }
    }

    /// List keys with a prefix (admin listings; not on hot paths).
    pub async fn scan_prefix(&self, prefix: &str) -> SResult<Vec<(String, Vec<u8>)>> {
        match self {
            Store::Memory(s) => Ok(s.inner.lock().await.scan_prefix(prefix)),
            Store::File(s) => Ok(s.mem.inner.lock().await.scan_prefix(prefix)),
            Store::Redis(s) => s.scan_prefix(prefix).await,
        }
    }
}

// ---------------------------------------------------------------- memory

#[derive(Default)]
struct MemInner {
    kv: HashMap<String, (Vec<u8>, Option<Instant>)>,
    lists: HashMap<String, Vec<Vec<u8>>>,
}

impl MemInner {
    fn alive(&self, key: &str) -> bool {
        match self.kv.get(key) {
            Some((_, Some(exp))) => *exp > Instant::now(),
            Some((_, None)) => true,
            None => false,
        }
    }
    fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        if !self.alive(key) {
            self.kv.remove(key);
            return None;
        }
        self.kv.get(key).map(|(v, _)| v.clone())
    }
    fn put(&mut self, key: &str, value: &[u8], ttl: Option<Duration>) {
        let exp = ttl.map(|d| Instant::now() + d);
        self.kv.insert(key.to_string(), (value.to_vec(), exp));
    }
    fn put_if_absent(&mut self, key: &str, value: &[u8], ttl: Option<Duration>) -> bool {
        if self.alive(key) {
            return false;
        }
        self.put(key, value, ttl);
        true
    }
    fn delete(&mut self, key: &str) -> bool {
        self.kv.remove(key).is_some()
    }
    fn take(&mut self, key: &str) -> Option<Vec<u8>> {
        if !self.alive(key) {
            self.kv.remove(key);
            return None;
        }
        self.kv.remove(key).map(|(v, _)| v)
    }
    fn incr(&mut self, key: &str) -> i64 {
        let current = self
            .get(key)
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let next = current + 1;
        self.put(key, next.to_string().as_bytes(), None);
        next
    }
    fn list_push(&mut self, key: &str, value: &[u8], max: usize) {
        let list = self.lists.entry(key.to_string()).or_default();
        list.push(value.to_vec());
        if list.len() > max {
            let excess = list.len() - max;
            list.drain(0..excess);
        }
    }
    fn list_drain(&mut self, key: &str) -> Vec<Vec<u8>> {
        self.lists.remove(key).unwrap_or_default()
    }
    fn scan_prefix(&mut self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        let now = Instant::now();
        let mut out: Vec<(String, Vec<u8>)> = self
            .kv
            .iter()
            .filter(|(k, (_, exp))| k.starts_with(prefix) && exp.map(|e| e > now).unwrap_or(true))
            .map(|(k, (v, _))| (k.clone(), v.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

pub struct MemoryStore {
    inner: Mutex<MemInner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore {
            inner: Mutex::new(MemInner::default()),
        }
    }
}

// ---------------------------------------------------------------- file

/// Memory store with a JSON snapshot persisted on every mutation
/// (atomic tmp+rename). TTLs are persisted as absolute unix deadlines.
pub struct FileStore {
    mem: MemoryStore,
    path: String,
    write_lock: Mutex<()>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Snapshot {
    kv: Vec<(String, String, Option<u64>)>, // key, b64 value, unix deadline
    lists: Vec<(String, Vec<String>)>,
}

impl FileStore {
    pub async fn open(path: &str) -> SResult<FileStore> {
        let mem = MemoryStore::new();
        if let Ok(raw) = tokio::fs::read_to_string(path).await {
            let snap: Snapshot = serde_json::from_str(&raw).map_err(serr)?;
            let now = aauth_core::now_unix();
            let mut inner = mem.inner.lock().await;
            for (k, v, deadline) in snap.kv {
                let ttl = match deadline {
                    Some(d) if d <= now => continue,
                    Some(d) => Some(Duration::from_secs(d - now)),
                    None => None,
                };
                let value = aauth_core::b64::decode(&v).map_err(serr)?;
                inner.put(&k, &value, ttl);
            }
            for (k, items) in snap.lists {
                for item in items {
                    let value = aauth_core::b64::decode(&item).map_err(serr)?;
                    inner.list_push(&k, &value, usize::MAX);
                }
            }
        }
        Ok(FileStore {
            mem,
            path: path.to_string(),
            write_lock: Mutex::new(()),
        })
    }

    async fn persist(&self) -> SResult<()> {
        let _guard = self.write_lock.lock().await;
        let snap = {
            let mut inner = self.mem.inner.lock().await;
            let now_i = Instant::now();
            let now_u = aauth_core::now_unix();
            inner
                .kv
                .retain(|_, (_, exp)| exp.map(|e| e > now_i).unwrap_or(true));
            Snapshot {
                kv: inner
                    .kv
                    .iter()
                    .map(|(k, (v, exp))| {
                        let deadline =
                            exp.map(|e| now_u + e.saturating_duration_since(now_i).as_secs());
                        (k.clone(), aauth_core::b64::encode(v), deadline)
                    })
                    .collect(),
                lists: inner
                    .lists
                    .iter()
                    .map(|(k, items)| {
                        (
                            k.clone(),
                            items.iter().map(|v| aauth_core::b64::encode(v)).collect(),
                        )
                    })
                    .collect(),
            }
        };
        let tmp = format!("{}.tmp", self.path);
        let data = serde_json::to_vec(&snap).map_err(serr)?;
        tokio::fs::write(&tmp, &data).await.map_err(serr)?;
        tokio::fs::rename(&tmp, &self.path).await.map_err(serr)?;
        Ok(())
    }
}

// ---------------------------------------------------------------- redis

/// Minimal RESP2 client: a small pool of TCP connections, reconnect on error.
/// Commands used: GET, SET (PX/NX), DEL, GETDEL, INCR, RPUSH, LTRIM, LRANGE,
/// SCAN, MGET, MULTI/EXEC (for list drain).
pub struct RedisStore {
    addr: String,
    prefix: String,
    pool: Mutex<Vec<RedisConn>>,
}

struct RedisConn {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

#[derive(Debug)]
#[allow(dead_code)] // RESP2 variants kept for protocol completeness
enum Resp {
    Simple(String),
    Error(String),
    Int(i64),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<Resp>>),
}

impl RedisConn {
    async fn connect(addr: &str) -> SResult<RedisConn> {
        let stream = TcpStream::connect(addr).await.map_err(serr)?;
        stream.set_nodelay(true).ok();
        let (r, w) = stream.into_split();
        Ok(RedisConn {
            reader: BufReader::new(r),
            writer: w,
        })
    }

    async fn command(&mut self, args: &[&[u8]]) -> SResult<Resp> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
        for a in args {
            buf.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            buf.extend_from_slice(a);
            buf.extend_from_slice(b"\r\n");
        }
        self.writer.write_all(&buf).await.map_err(serr)?;
        self.read_reply().await
    }

    async fn read_line(&mut self) -> SResult<String> {
        let mut line = Vec::new();
        loop {
            let b = self.reader.read_u8().await.map_err(serr)?;
            if b == b'\r' {
                let n = self.reader.read_u8().await.map_err(serr)?;
                if n != b'\n' {
                    return Err(StorageError("redis protocol error".into()));
                }
                break;
            }
            line.push(b);
            if line.len() > 64 * 1024 {
                return Err(StorageError("redis line too long".into()));
            }
        }
        String::from_utf8(line).map_err(serr)
    }

    async fn read_reply(&mut self) -> SResult<Resp> {
        let line = self.read_line().await?;
        let (tag, rest) = line.split_at(1);
        match tag {
            "+" => Ok(Resp::Simple(rest.to_string())),
            "-" => Ok(Resp::Error(rest.to_string())),
            ":" => Ok(Resp::Int(rest.parse().map_err(serr)?)),
            "$" => {
                let len: i64 = rest.parse().map_err(serr)?;
                if len < 0 {
                    return Ok(Resp::Bulk(None));
                }
                let mut data = vec![0u8; len as usize];
                self.reader.read_exact(&mut data).await.map_err(serr)?;
                let mut crlf = [0u8; 2];
                self.reader.read_exact(&mut crlf).await.map_err(serr)?;
                Ok(Resp::Bulk(Some(data)))
            }
            "*" => {
                let len: i64 = rest.parse().map_err(serr)?;
                if len < 0 {
                    return Ok(Resp::Array(None));
                }
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    items.push(Box::pin(self.read_reply()).await?);
                }
                Ok(Resp::Array(Some(items)))
            }
            _ => Err(StorageError("redis protocol error".into())),
        }
    }
}

impl RedisStore {
    pub fn new(addr: &str, prefix: &str) -> RedisStore {
        RedisStore {
            addr: addr.to_string(),
            prefix: prefix.to_string(),
            pool: Mutex::new(Vec::new()),
        }
    }

    fn k(&self, key: &str) -> Vec<u8> {
        format!("{}{}", self.prefix, key).into_bytes()
    }

    async fn conn(&self) -> SResult<RedisConn> {
        if let Some(c) = self.pool.lock().await.pop() {
            return Ok(c);
        }
        RedisConn::connect(&self.addr).await
    }

    async fn release(&self, conn: RedisConn) {
        let mut pool = self.pool.lock().await;
        if pool.len() < 8 {
            pool.push(conn);
        }
    }

    async fn run(&self, args: &[&[u8]]) -> SResult<Resp> {
        // one retry with a fresh connection on transport error
        for attempt in 0..2 {
            let mut conn = if attempt == 0 {
                self.conn().await?
            } else {
                RedisConn::connect(&self.addr).await?
            };
            match conn.command(args).await {
                Ok(Resp::Error(e)) => return Err(StorageError(format!("redis: {e}"))),
                Ok(resp) => {
                    self.release(conn).await;
                    return Ok(resp);
                }
                Err(_) if attempt == 0 => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    async fn get(&self, key: &str) -> SResult<Option<Vec<u8>>> {
        match self.run(&[b"GET", &self.k(key)]).await? {
            Resp::Bulk(v) => Ok(v),
            _ => Err(StorageError("unexpected GET reply".into())),
        }
    }

    async fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> SResult<()> {
        let k = self.k(key);
        let px;
        let mut args: Vec<&[u8]> = vec![b"SET", &k, value];
        if let Some(ttl) = ttl {
            px = ttl.as_millis().max(1).to_string();
            args.push(b"PX");
            args.push(px.as_bytes());
        }
        self.run(&args).await.map(|_| ())
    }

    async fn put_if_absent(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> SResult<bool> {
        let k = self.k(key);
        let px;
        let mut args: Vec<&[u8]> = vec![b"SET", &k, value, b"NX"];
        if let Some(ttl) = ttl {
            px = ttl.as_millis().max(1).to_string();
            args.push(b"PX");
            args.push(px.as_bytes());
        }
        match self.run(&args).await? {
            Resp::Simple(_) => Ok(true),
            Resp::Bulk(None) => Ok(false),
            _ => Err(StorageError("unexpected SET NX reply".into())),
        }
    }

    async fn delete(&self, key: &str) -> SResult<bool> {
        match self.run(&[b"DEL", &self.k(key)]).await? {
            Resp::Int(n) => Ok(n > 0),
            _ => Err(StorageError("unexpected DEL reply".into())),
        }
    }

    async fn take(&self, key: &str) -> SResult<Option<Vec<u8>>> {
        // GETDEL requires Redis >= 6.2
        match self.run(&[b"GETDEL", &self.k(key)]).await? {
            Resp::Bulk(v) => Ok(v),
            _ => Err(StorageError("unexpected GETDEL reply".into())),
        }
    }

    async fn incr(&self, key: &str) -> SResult<i64> {
        match self.run(&[b"INCR", &self.k(key)]).await? {
            Resp::Int(n) => Ok(n),
            _ => Err(StorageError("unexpected INCR reply".into())),
        }
    }

    async fn list_push(&self, key: &str, value: &[u8], max: usize) -> SResult<()> {
        let k = self.k(key);
        self.run(&[b"RPUSH", &k, value]).await?;
        let start = format!("-{max}");
        self.run(&[b"LTRIM", &k, start.as_bytes(), b"-1"]).await?;
        Ok(())
    }

    async fn list_drain(&self, key: &str) -> SResult<Vec<Vec<u8>>> {
        // MULTI LRANGE DEL EXEC — atomic read-and-clear
        let k = self.k(key);
        let mut conn = self.conn().await?;
        let result: SResult<Vec<Vec<u8>>> = async {
            conn.command(&[b"MULTI"]).await?;
            conn.command(&[b"LRANGE", &k, b"0", b"-1"]).await?;
            conn.command(&[b"DEL", &k]).await?;
            match conn.command(&[b"EXEC"]).await? {
                Resp::Array(Some(mut replies)) if replies.len() == 2 => match replies.remove(0) {
                    Resp::Array(Some(items)) => items
                        .into_iter()
                        .map(|r| match r {
                            Resp::Bulk(Some(v)) => Ok(v),
                            _ => Err(StorageError("unexpected LRANGE item".into())),
                        })
                        .collect(),
                    Resp::Array(None) => Ok(Vec::new()),
                    _ => Err(StorageError("unexpected EXEC reply".into())),
                },
                _ => Err(StorageError("unexpected EXEC reply".into())),
            }
        }
        .await;
        if result.is_ok() {
            self.release(conn).await;
        }
        result
    }

    async fn scan_prefix(&self, prefix: &str) -> SResult<Vec<(String, Vec<u8>)>> {
        let pattern = format!("{}{}*", self.prefix, prefix);
        let mut cursor = "0".to_string();
        let mut keys: Vec<String> = Vec::new();
        loop {
            let reply = self
                .run(&[
                    b"SCAN",
                    cursor.as_bytes(),
                    b"MATCH",
                    pattern.as_bytes(),
                    b"COUNT",
                    b"200",
                ])
                .await?;
            match reply {
                Resp::Array(Some(mut parts)) if parts.len() == 2 => {
                    let next = match parts.remove(0) {
                        Resp::Bulk(Some(c)) => String::from_utf8(c).map_err(serr)?,
                        _ => return Err(StorageError("unexpected SCAN cursor".into())),
                    };
                    if let Resp::Array(Some(items)) = parts.remove(0) {
                        for item in items {
                            if let Resp::Bulk(Some(k)) = item {
                                keys.push(String::from_utf8(k).map_err(serr)?);
                            }
                        }
                    }
                    cursor = next;
                    if cursor == "0" {
                        break;
                    }
                }
                _ => return Err(StorageError("unexpected SCAN reply".into())),
            }
        }
        keys.sort();
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Resp::Bulk(Some(v)) = self.run(&[b"GET", key.as_bytes()]).await? {
                let logical = key.strip_prefix(&self.prefix).unwrap_or(&key).to_string();
                out.push((logical, v));
            }
        }
        Ok(out)
    }
}

/// Construct the configured backend.
pub async fn open(cfg: &crate::config::StorageConfig) -> SResult<Store> {
    match cfg.backend.as_str() {
        "memory" => Ok(Store::Memory(MemoryStore::new())),
        "file" => Ok(Store::File(
            FileStore::open(cfg.path.as_deref().unwrap()).await?,
        )),
        "redis" => Ok(Store::Redis(RedisStore::new(
            cfg.redis_addr.as_deref().unwrap(),
            &cfg.key_prefix,
        ))),
        other => Err(StorageError(format!("unknown backend {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip(store: &Store) {
        let uniq = aauth_core::rand_id(8);
        let k = |s: &str| format!("t:{uniq}:{s}");

        // put / get / delete
        store.put(&k("a"), b"hello", None).await.unwrap();
        assert_eq!(
            store.get(&k("a")).await.unwrap().as_deref(),
            Some(&b"hello"[..])
        );
        assert!(store.delete(&k("a")).await.unwrap());
        assert!(store.get(&k("a")).await.unwrap().is_none());

        // put_if_absent atomicity
        assert!(store.put_if_absent(&k("b"), b"1", None).await.unwrap());
        assert!(!store.put_if_absent(&k("b"), b"2", None).await.unwrap());
        assert_eq!(
            store.get(&k("b")).await.unwrap().as_deref(),
            Some(&b"1"[..])
        );

        // take = get + delete
        assert_eq!(
            store.take(&k("b")).await.unwrap().as_deref(),
            Some(&b"1"[..])
        );
        assert!(store.take(&k("b")).await.unwrap().is_none());

        // incr
        assert_eq!(store.incr(&k("c")).await.unwrap(), 1);
        assert_eq!(store.incr(&k("c")).await.unwrap(), 2);

        // lists
        store.list_push(&k("l"), b"x", 10).await.unwrap();
        store.list_push(&k("l"), b"y", 10).await.unwrap();
        let drained = store.list_drain(&k("l")).await.unwrap();
        assert_eq!(drained, vec![b"x".to_vec(), b"y".to_vec()]);
        assert!(store.list_drain(&k("l")).await.unwrap().is_empty());

        // list trim to max
        for i in 0..5 {
            store.list_push(&k("m"), &[i], 3).await.unwrap();
        }
        assert_eq!(
            store.list_drain(&k("m")).await.unwrap(),
            vec![vec![2], vec![3], vec![4]]
        );

        // scan_prefix
        store.put(&k("p1"), b"1", None).await.unwrap();
        store.put(&k("p2"), b"2", None).await.unwrap();
        let found = store.scan_prefix(&format!("t:{uniq}:p")).await.unwrap();
        assert_eq!(found.len(), 2);

        // ttl expiry
        store
            .put(&k("ttl"), b"v", Some(Duration::from_millis(80)))
            .await
            .unwrap();
        assert!(store.get(&k("ttl")).await.unwrap().is_some());
        tokio::time::sleep(Duration::from_millis(160)).await;
        assert!(store.get(&k("ttl")).await.unwrap().is_none());
    }

    // NOTE: `open()` is defined above this test module.

    #[tokio::test]
    async fn memory_backend() {
        let store = Store::Memory(MemoryStore::new());
        roundtrip(&store).await;
    }

    #[tokio::test]
    async fn file_backend() {
        let path = format!(
            "{}/apd-test-{}.json",
            std::env::temp_dir().display(),
            aauth_core::rand_id(8)
        );
        let store = Store::File(FileStore::open(&path).await.unwrap());
        roundtrip(&store).await;
        // reload persists kv
        store.put("persist:k", b"v", None).await.unwrap();
        drop(store);
        let store2 = Store::File(FileStore::open(&path).await.unwrap());
        assert_eq!(
            store2.get("persist:k").await.unwrap().as_deref(),
            Some(&b"v"[..])
        );
        std::fs::remove_file(&path).ok();
    }

    /// Runs only when APD_TEST_REDIS=host:port is set (exercises the
    /// hand-rolled RESP2 client against a real server).
    #[tokio::test]
    async fn redis_backend() {
        let Ok(addr) = std::env::var("APD_TEST_REDIS") else {
            eprintln!("skipping redis_backend (set APD_TEST_REDIS=host:port to run)");
            return;
        };
        let store = Store::Redis(RedisStore::new(&addr, "apdtest:"));
        roundtrip(&store).await;
    }
}
