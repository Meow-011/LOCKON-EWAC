// ── Offline basemap ────────────────────────────────────────────────────────
//
// A PMTiles archive is read by byte range: the reader fetches a header, then an
// index, then individual tiles, each as an offset and a length. In a browser
// that is an HTTP range request; here the file is on local disk, and the
// question is how the renderer gets at it.
//
// Two commands rather than a filesystem permission.
//
// Tauri's asset protocol or `tauri-plugin-fs` would both work and both hand the
// renderer a general ability to read files, scoped by a glob. This application
// has spent effort going the other way -- `opener:default`, `shell:allow-execute`
// and `sql:allow-select` were all removed because nothing needed them -- and the
// renderer here holds `sql:allow-execute` and spawns the sidecar, so a path
// traversal in it would be worth more than usual. These two commands can read
// exactly one file, whose path the renderer never supplies and cannot influence.
//
// The cost is that this is less flexible: the basemap lives at one place with
// one name. For a file an operator installs once, that is the right trade, and
// `basemap_status` tells them where it goes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use tauri::Manager;

/// Where the archive lives. One path, derived from Tauri's own app-data
/// directory, never from anything the renderer sends.
fn basemap_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("the application data directory could not be resolved: {e}"))?;
    Ok(dir.join("basemap.pmtiles"))
}

#[derive(serde::Serialize)]
pub struct BasemapStatus {
    /// Whether a file is installed and readable.
    installed: bool,
    /// Always returned, so the settings page can tell the operator where to put one.
    path: String,
    /// `None` when nothing is installed, rather than 0 -- a zero-byte file and no
    /// file at all need different advice.
    size_bytes: Option<u64>,
}

/// Whether an offline basemap is installed, and where it would go.
#[tauri::command(async)]
pub fn basemap_status(app: tauri::AppHandle) -> Result<BasemapStatus, String> {
    let path = basemap_path(&app)?;
    let display = path.to_string_lossy().to_string();
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(BasemapStatus {
            installed: true,
            path: display,
            size_bytes: Some(meta.len()),
        }),
        // A directory of that name, or an unreadable entry, is reported as not
        // installed with the path shown -- the operator can see what is there.
        _ => Ok(BasemapStatus {
            installed: false,
            path: display,
            size_bytes: None,
        }),
    }
}

/// The largest single read this will serve.
///
/// A PMTiles tile is a few kilobytes and its root index a few hundred; the
/// largest legitimate read is a leaf directory. 16 MiB is far above any of them
/// and far below a size that would let a loop in the renderer exhaust memory by
/// asking for the whole archive at once.
const MAX_RANGE: u64 = 16 * 1024 * 1024;

/// Read `length` bytes at `offset` from the installed basemap.
///
/// Returns the bytes base64-encoded, because Tauri's IPC carries JSON and a
/// `Vec<u8>` crosses it as an array of numbers -- roughly four times the size for
/// a payload the map requests hundreds of times while panning.
#[tauri::command(async)]
pub fn read_basemap_range(
    app: tauri::AppHandle,
    offset: u64,
    length: u64,
) -> Result<String, String> {
    if length == 0 {
        return Err("a zero-length read was requested".into());
    }
    if length > MAX_RANGE {
        return Err(format!(
            "a {length}-byte read was requested; the limit is {MAX_RANGE}"
        ));
    }

    let path = basemap_path(&app)?;
    let mut file = File::open(&path)
        .map_err(|e| format!("the basemap could not be opened: {e}"))?;

    let size = file
        .metadata()
        .map_err(|e| format!("the basemap could not be measured: {e}"))?
        .len();
    if offset >= size {
        return Err(format!(
            "offset {offset} is past the end of a {size}-byte archive"
        ));
    }

    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seek to {offset} failed: {e}"))?;

    // Clamped to what is actually there. A reader asking past the end gets the
    // short tail rather than an error, which is what an HTTP range request would
    // give it and what the PMTiles reader expects.
    let want = length.min(size - offset) as usize;
    let mut buf = vec![0u8; want];
    file.read_exact(&mut buf)
        .map_err(|e| format!("read of {want} bytes at {offset} failed: {e}"))?;

    Ok(base64_encode(&buf))
}

/// Base64, written out rather than taken as a dependency.
///
/// One table and three shifts; adding a crate for it would be a larger change to
/// the dependency set than the function is to this file.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64_encode;

    // The encoder is the one piece here with no Tauri handle in the way, and the
    // one where an off-by-one is silent: a wrong pad length produces bytes the
    // PMTiles reader parses as a corrupt header rather than as an error.
    #[test]
    fn encodes_the_rfc_4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn encodes_bytes_that_are_not_text() {
        // The PMTiles header begins with bytes outside ASCII, and a `+`/`/`
        // mix-up only shows up on data like this.
        assert_eq!(base64_encode(&[0x00, 0xff, 0xfe]), "AP/+");
        assert_eq!(base64_encode(&[0xfb, 0xff, 0xbf]), "+/+/");
    }
}
