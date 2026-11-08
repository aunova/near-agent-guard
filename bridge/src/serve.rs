//! The agent's only exit: a Unix socket taking one JSON request line per connection, and the
//! scripted `replay` path that feeds a file through the same gate.

use std::fs::{self, File, Permissions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::audit::Origin;
use crate::gate::Gate;

/// Largest request the screen accepts. One byte more is passed on, so the screen answers
/// `request_too_large` instead of judging a truncated request.
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Total time a client gets to send its request line, and to take the response.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Serves `socket` until killed, one connection at a time.
pub fn serve(socket: &Path, gate: &Gate) -> Result<()> {
    prepare_socket_path(socket)?;
    let listener =
        UnixListener::bind(socket).with_context(|| format!("cannot bind {}", socket.display()))?;
    fs::set_permissions(socket, Permissions::from_mode(0o600))
        .with_context(|| format!("cannot set mode 0600 on {}", socket.display()))?;
    eprintln!("guard: serving {} (mode 0600, one request per connection)", socket.display());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle(&stream, gate) {
                    eprintln!("guard: connection dropped: {error:#}");
                }
            }
            Err(error) => eprintln!("guard: accept failed: {}", error.kind()),
        }
    }
    Ok(())
}

/// Removes a stale socket; refuses a live one, and anything that is not a socket.
fn prepare_socket_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                bail!("{} is a live socket; another guard is serving it", path.display());
            }
            fs::remove_file(path).with_context(|| format!("cannot remove stale socket {}", path.display()))
        }
        Ok(_) => bail!("{} exists and is not a socket; refusing to replace it", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn handle(stream: &UnixStream, gate: &Gate) -> Result<()> {
    let deadline = Instant::now() + CLIENT_TIMEOUT;
    let Some(raw) = read_request(stream, deadline)? else {
        return Ok(()); // connected and closed without sending anything
    };
    let response = gate.gate(&raw, Origin::LlmAgent);
    let mut line = serde_json::to_vec(&response)?;
    line.push(b'\n');
    stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;
    let mut writer = stream;
    writer.write_all(&line)?;
    Ok(())
}

/// Reads the first line of a connection: up to `MAX_REQUEST_BYTES + 1` bytes, by `deadline`
/// in total (a per-read timeout alone would let a slow client hold the serial loop forever).
fn read_request(stream: &UnixStream, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut reader = stream;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "client did not send a line in time"));
        }
        stream.set_read_timeout(Some(remaining))?;
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok((!request.is_empty()).then_some(request));
        }
        request.extend_from_slice(chunk.get(..read).unwrap_or_default());
        if let Some(newline) = request.iter().position(|byte| *byte == b'\n') {
            request.truncate(newline.min(MAX_REQUEST_BYTES + 1));
            return Ok(Some(request));
        }
        if request.len() > MAX_REQUEST_BYTES {
            request.truncate(MAX_REQUEST_BYTES + 1);
            return Ok(Some(request));
        }
    }
}

/// Feeds every non-empty line of `file` through the gate, printing one response per line.
pub fn replay(file: &Path, gate: &Gate) -> Result<()> {
    let file = File::open(file).with_context(|| format!("cannot open {}", file.display()))?;
    let mut reader = BufReader::new(file);
    let mut stdout = io::stdout().lock();
    while let Some(raw) = read_capped_line(&mut reader, MAX_REQUEST_BYTES)? {
        if raw.is_empty() {
            continue;
        }
        let response = gate.gate(&raw, Origin::Replay);
        serde_json::to_writer(&mut stdout, &response)?;
        writeln!(stdout)?;
        stdout.flush()?;
    }
    Ok(())
}

/// Reads one `\n`-terminated line, keeping at most `cap + 1` bytes of it; the rest of an
/// over-long line is skipped. `None` at end of input.
fn read_capped_line(reader: &mut impl BufRead, cap: usize) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    if reader.by_ref().take(cap as u64 + 1).read_until(b'\n', &mut line)? == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() > cap {
        let mut discard = Vec::new();
        while reader.read_until(b'\n', &mut discard)? > 0 && discard.last() != Some(&b'\n') {
            discard.clear();
        }
    }
    Ok(Some(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_split_and_over_long_lines_are_capped_then_skipped() {
        let long = "x".repeat(50);
        let input = format!("first\n{long}\nlast");
        let mut reader = BufReader::new(input.as_bytes());
        assert_eq!(read_capped_line(&mut reader, 10).unwrap().unwrap(), b"first");
        assert_eq!(read_capped_line(&mut reader, 10).unwrap().unwrap(), "x".repeat(11).as_bytes());
        assert_eq!(read_capped_line(&mut reader, 10).unwrap().unwrap(), b"last");
        assert_eq!(read_capped_line(&mut reader, 10).unwrap(), None);
    }

    #[test]
    fn a_line_of_exactly_cap_bytes_is_kept_whole() {
        let input = format!("{}\n", "y".repeat(10));
        let mut reader = BufReader::new(input.as_bytes());
        assert_eq!(read_capped_line(&mut reader, 10).unwrap().unwrap(), "y".repeat(10).as_bytes());
    }

    #[test]
    fn socket_request_stops_at_the_newline_or_one_past_the_cap() {
        let (client, server) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        (&client).write_all(b"{\"tool\":\"pay\"}\ntrailing").unwrap();
        assert_eq!(read_request(&server, deadline).unwrap().unwrap(), b"{\"tool\":\"pay\"}");

        let (client, server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = (&client).write_all(&vec![b'z'; MAX_REQUEST_BYTES * 2]);
        });
        let request = read_request(&server, deadline).unwrap().unwrap();
        assert_eq!(request.len(), MAX_REQUEST_BYTES + 1);
        drop(server);
        writer.join().unwrap();
    }

    #[test]
    fn a_silent_client_hits_the_deadline() {
        let (_client, server) = UnixStream::pair().unwrap();
        let error = read_request(&server, Instant::now() + Duration::from_millis(50)).unwrap_err();
        assert!(matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock));
    }

    #[test]
    fn stale_socket_is_replaced_but_live_sockets_and_files_are_refused() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/unit-tmp")
            .join(format!("serve-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let stale = dir.join("stale.sock");
        let _ = fs::remove_file(&stale);
        drop(UnixListener::bind(&stale).unwrap()); // leaves a socket file nobody listens on
        prepare_socket_path(&stale).unwrap();
        assert!(!stale.exists());

        let live = dir.join("live.sock");
        let _ = fs::remove_file(&live);
        let _listener = UnixListener::bind(&live).unwrap();
        assert!(prepare_socket_path(&live).unwrap_err().to_string().contains("live socket"));

        let file = dir.join("not-a-socket");
        fs::write(&file, b"keep me").unwrap();
        assert!(prepare_socket_path(&file).unwrap_err().to_string().contains("not a socket"));
        assert_eq!(fs::read(&file).unwrap(), b"keep me");
        fs::remove_dir_all(&dir).unwrap();
    }
}
