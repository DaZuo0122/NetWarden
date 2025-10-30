use std::path::{Path, PathBuf};
use std::{env, fs, io};
use x509_parser::prelude::FromDer;
use anyhow::Result;

// Platform-specific modules - only define them once and use conditional compilation
#[cfg(target_os = "linux")]
mod platform_impl {
    use super::{CertificateResult, load_certs_from_paths_internal};

    pub fn load_native_certs_raw() -> super::CertificateResult<Vec<u8>> {
        let likely_locations = openssl_probe::probe();
        let paths = super::CertPaths {
            file: likely_locations.cert_file,
            dirs: likely_locations.cert_dir.into_iter().collect(),
        };
        paths.load()
    }
}

#[cfg(windows)]
mod platform_impl {
    use super::CertificateResult;

    pub fn load_native_certs_raw() -> super::CertificateResult<Vec<u8>> {
        let mut result = CertificateResult::default();
        let current_user_store = match schannel::cert_store::CertStore::open_current_user("ROOT") {
            Ok(store) => store,
            Err(err) => {
                result.errors.push(::anyhow::anyhow!("failed to open current user certificate store: {}", err));
                return result;
            }
        };

        for cert in current_user_store.certs() {
            if cert.is_time_valid().unwrap_or(true) {
                result.certs.push(cert.to_der().to_vec());
            }
        }

        result
    }
}

// Use platform-specific implementation based on target OS
#[cfg(target_os = "linux")]
use platform_impl as platform;
#[cfg(windows)]
use platform_impl as platform;

// Error handling for unsupported platforms
#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("This crate only supports Linux and Windows platforms");

// Define a structure to return certificate loading results
#[derive(Debug, Default)]
pub struct CertificateResult<T> {
    /// Any certificates that were successfully loaded.
    pub certs: Vec<T>,
    /// Any errors encountered while loading certificates.
    pub errors: Vec<anyhow::Error>,
}

/// Load certificates found in the platform's native certificate store.
pub fn load_native_certs_raw() -> CertificateResult<Vec<u8>> {
    let paths = CertPaths::from_env();
    match (&paths.dirs, &paths.file) {
        (v, _) if !v.is_empty() => paths.load(),
        (_, Some(_)) => paths.load(),
        _ => platform::load_native_certs_raw(),
    }
}

/// Certificate paths from `SSL_CERT_FILE` and/or `SSL_CERT_DIR`.
struct CertPaths {
    file: Option<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl CertPaths {
    fn from_env() -> Self {
        Self {
            file: env::var_os(ENV_CERT_FILE).map(PathBuf::from),
            // Read `SSL_CERT_DIR`, split it on the platform delimiter (`:` on Unix, `;` on Windows),
            // and return the entries as `PathBuf`s.
            //
            // See <https://docs.openssl.org/3.5/man1/openssl-rehash/#options>
            dirs: match env::var_os(ENV_CERT_DIR) {
                Some(dirs) => env::split_paths(&dirs).collect(),
                None => Vec::new(),
            },
        }
    }

    /// Load certificates from the paths.
    fn load(&self) -> CertificateResult<Vec<u8>> {
        load_certs_from_paths_internal(self.file.as_deref(), &self.dirs)
    }
}

/// Load certificates from the given paths.
pub fn load_certs_from_paths(file: Option<&Path>, dir: Option<&Path>) -> CertificateResult<Vec<u8>> {
    let dir = match dir {
        Some(d) => vec![d],
        None => Vec::new(),
    };

    load_certs_from_paths_internal(file, dir.as_ref())
}

fn load_certs_from_paths_internal(
    file: Option<&Path>,
    dir: &[impl AsRef<Path>],
) -> CertificateResult<Vec<u8>> {
    let mut out = CertificateResult::default();
    if file.is_none() && dir.is_empty() {
        return out;
    }

    if let Some(cert_file) = file {
        load_certs(cert_file, &mut out);
    }

    for cert_dir in dir.iter() {
        load_certs_from_dir(cert_dir.as_ref(), &mut out);
    }

    out
}

/// Load certificate from certificate directory
fn load_certs_from_dir(dir: &Path, out: &mut CertificateResult<Vec<u8>>) {
    let dir_reader = match fs::read_dir(dir) {
        Ok(reader) => reader,
        Err(err) => {
            out.errors.push(err.into());
            return;
        }
    };

    for entry in dir_reader {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                out.errors.push(err.into());
                continue;
            }
        };

        let path = entry.path();

        // `openssl rehash` used to create this directory uses symlinks. So,
        // make sure we resolve them.
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Dangling symlink
                continue;
            }
            Err(e) => {
                out.errors.push(e.into());
                continue;
            }
        };

        if metadata.is_file() {
            load_certs(&path, out);
        }
    }
}

fn load_certs(path: &Path, out: &mut CertificateResult<Vec<u8>>) {
    // Try to read as PEM first
    if let Ok(content) = fs::read_to_string(path) {
        // Try to parse as PEM
        if content.contains("-----BEGIN CERTIFICATE-----") {
            let pem_blocks = content.split("-----BEGIN CERTIFICATE-----")
                .skip(1)
                .map(|block| {
                    let cert_data = block.split("-----END CERTIFICATE-----")
                        .next()
                        .unwrap_or("");
                    cert_data.replace("\n", "").replace("\r", "")
                })
                .filter(|s| !s.is_empty());

            for pem_body in pem_blocks {
                if let Ok(decoded) = base64::decode(&pem_body) {
                    out.certs.push(decoded);
                }
            }
        } else {
            // If it's not PEM format, try to load as DER directly
            if let Ok(der_bytes) = fs::read(path) {
                out.certs.push(der_bytes);
            }
        }
    } else {
        // Try to load as DER directly
        if let Ok(der_bytes) = fs::read(path) {
            out.certs.push(der_bytes);
        }
    }
}

const ENV_CERT_FILE: &str = "SSL_CERT_FILE";
const ENV_CERT_DIR: &str = "SSL_CERT_DIR";

mod base64 {
    // A simple base64 decoder for our use case
    pub fn decode(input: &str) -> Result<Vec<u8>, String> {
        const BASE64_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        let mut result = Vec::new();
        let mut current: u32 = 0;
        let mut bits = 0;
        
        for ch in input.chars() {
            if ch == '=' { 
                break; // Padding, stop here
            }
            
            if let Some(pos) = BASE64_CHARS.find(ch) {
                current = (current << 6) | (pos as u32);
                bits += 6;
                
                if bits >= 8 {
                    bits -= 8;
                    let byte = ((current >> bits) & 0xFF) as u8;
                    result.push(byte);
                }
            }
        }
        
        Ok(result)
    }
}

// Define a structure to hold certificate information
#[derive(Debug)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub signature_algorithm: String,
}

impl std::fmt::Display for CertificateInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Subject: {}", self.subject)?;
        writeln!(f, "Issuer: {}", self.issuer)?;
        writeln!(f, "Valid From: {}", self.not_before)?;
        writeln!(f, "Valid Until: {}", self.not_after)?;
        writeln!(f, "Serial Number: {}", self.serial_number)?;
        writeln!(f, "Signature Algorithm: {}", self.signature_algorithm)?;
        Ok(())
    }
}

pub fn parse_certificate(cert_der: &[u8]) -> Result<CertificateInfo> {
    let (_, x509) = x509_parser::prelude::X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

    let subject = x509.subject().to_string();
    let issuer = x509.issuer().to_string();
    let not_before = format!("{}", x509.validity().not_before);
    let not_after = format!("{}", x509.validity().not_after);
    let serial_number = format!("{}", x509.serial);
    let signature_algorithm_oid = x509.signature_algorithm.oid().to_id_string();
    let signature_algorithm = format!("{}", signature_algorithm_oid);

    Ok(CertificateInfo {
        subject,
        issuer,
        not_before,
        not_after,
        serial_number,
        signature_algorithm,
    })
}

pub fn inspect_certs() -> CertificateResult<CertificateInfo> {
    let certs_result = load_native_certs_raw();
    
    let mut cert_infos = Vec::new();
    let mut errors = Vec::new();
    
    // Add any errors from loading
    for err in certs_result.errors {
        errors.push(anyhow::Error::from(err));
    }
    
    // Parse each certificate and add to results
    for cert_der in certs_result.certs {
        match parse_certificate(&cert_der) {
            Ok(cert_info) => cert_infos.push(cert_info),
            Err(e) => {
                errors.push(e);
            }
        }
    }
    
    CertificateResult {
        certs: cert_infos,
        errors,
    }
}