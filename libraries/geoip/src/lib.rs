use anyhow::{Ok, Result, anyhow};
use maxminddb::{Reader, geoip2};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use dunce;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Asn {
    /// Autonomous System number
    pub code: Option<String>,
    /// Autonomous System name
    pub name: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CountryInfo {
    /// ISO country code (e.g., "US")
    pub iso_code: Option<String>,
    /// English country name (if available)
    pub name_en: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpGeoInfo {
    pub country: CountryInfo,
    pub asn: Asn,
}

impl IpGeoInfo {
    pub fn new(asn: Asn, country: CountryInfo) -> Self {
        IpGeoInfo {
            country: country,
            asn: asn,
        }
    }
}

#[derive(Debug)]
pub struct GeoDbReader {
    asn_reader: Reader<Vec<u8>>,
    country_reader: Reader<Vec<u8>>,
}

impl GeoDbReader {
    pub fn lookup(&self, ip: &str) -> Result<IpGeoInfo> {
        let mut country_info = CountryInfo {
            iso_code: None,
            name_en: None,
        };
        let mut asn_info = Asn {
            code: None,
            name: None,
        };
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|e| anyhow!("invalid ip '{}': {}", ip, e))?;
        if let Some(country) = self.country_reader.lookup::<geoip2::Country>(ip_addr)? {
            if let Some(iso) = country.country.clone().and_then(|c| c.iso_code) {
                country_info.iso_code = Some(iso.to_string());
            }
            if let Some(country_names) = country.country.and_then(|c| c.names) {
                if let Some(country_name) = country_names.get("en") {
                    country_info.name_en = Some(country_name.to_string());
                }
            }
        }

        if let Some(asn) = self.asn_reader.lookup::<geoip2::Asn>(ip_addr)? {
            if let Some(asn_code) = asn.autonomous_system_number {
                asn_info.code = Some(asn_code.to_string());
            }
            if let Some(asn_name) = asn.autonomous_system_organization {
                asn_info.name = Some(asn_name.to_string());
            }
        }

        Ok(IpGeoInfo::new(asn_info, country_info))
    }
}

impl Default for GeoDbReader {
    fn default() -> GeoDbReader {
        GeoDbReader {
            asn_reader: open_asn_reader().unwrap(),
            country_reader: open_country_reader().unwrap(),
        }
    }
}

pub fn geo_lookup(ip_addr: &IpAddr) -> Result<IpGeoInfo> {
    let ip = ip_addr.to_string();
    let reader = GeoDbReader::default();
    reader.lookup(ip.as_str())
}

fn open_asn_reader() -> Result<Reader<Vec<u8>>> {
    let possible = gen_default_path_asn()?;
    for p in possible.iter() {
        if p.exists() {
            return Reader::open_readfile(p)
                .map_err(|e| anyhow!("failed to open ASN DB {:?}: {}", p, e));
        }
    }
    Err(anyhow!("no ASN database found in candidate paths"))
}

fn open_country_reader() -> Result<Reader<Vec<u8>>> {
    let possible = gen_default_path_country()?;
    for p in possible.iter() {
        if p.exists() {
            return Reader::open_readfile(p)
                .map_err(|e| anyhow!("failed to open Country DB {:?}: {}", p, e));
        }
    }
    Err(anyhow!("no Country database found in candidate paths"))
}

fn gen_default_path_asn() -> Result<[PathBuf; 3]> {
    let exec_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()))
        .unwrap_or(std::env::current_dir().unwrap_or_default());

    // Use dunce for path canonicalization on Windows to handle junctions and symlinks properly
    #[cfg(target_os = "windows")]
    let possible_paths = [
        dunce::canonicalize(exec_dir.join("data").join("GeoLite2-ASN.mmdb"))
            .unwrap_or_else(|_| exec_dir.join("data").join("GeoLite2-ASN.mmdb")), // For distribution
        dunce::canonicalize(
            std::env::current_dir()
                .unwrap_or_default()
                .join("data")
                .join("GeoLite2-ASN.mmdb"),
        )
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("data")
                .join("GeoLite2-ASN.mmdb")
        }), // For development
        dunce::canonicalize(Path::new("data").join("GeoLite2-ASN.mmdb"))
            .unwrap_or_else(|_| Path::new("data").join("GeoLite2-ASN.mmdb")), // Relative path
    ];

    #[cfg(target_os = "linux")]
    let possible_paths = [
        exec_dir.join("data").join("GeoLite2-ASN.mmdb"), // For distribution
        std::env::current_dir()
            .unwrap_or_default()
            .join("data")
            .join("GeoLite2-ASN.mmdb"), // For development
        Path::new("data").join("GeoLite2-ASN.mmdb"),     // Relative path
    ];

    Ok(possible_paths)
}

fn gen_default_path_country() -> Result<[PathBuf; 3]> {
    let exec_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()))
        .unwrap_or(std::env::current_dir().unwrap_or_default());

    // Use dunce for path canonicalization on Windows to handle junctions and symlinks properly
    #[cfg(target_os = "windows")]
    let possible_paths = [
        dunce::canonicalize(exec_dir.join("data").join("GeoLite2-Country.mmdb"))
            .unwrap_or_else(|_| exec_dir.join("data").join("GeoLite2-Country.mmdb")), // For distribution
        dunce::canonicalize(
            std::env::current_dir()
                .unwrap_or_default()
                .join("data")
                .join("GeoLite2-Country.mmdb"),
        )
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("data")
                .join("GeoLite2-Country.mmdb")
        }), // For development
        dunce::canonicalize(Path::new("data").join("GeoLite2-Country.mmdb"))
            .unwrap_or_else(|_| Path::new("data").join("GeoLite2-Country.mmdb")), // Relative path
    ];

    #[cfg(target_os = "linux")]
    let possible_paths = [
        exec_dir.join("data").join("GeoLite2-Country.mmdb"), // For distribution
        std::env::current_dir()
            .unwrap_or_default()
            .join("data")
            .join("GeoLite2-Country.mmdb"), // For development
        Path::new("data").join("GeoLite2-Country.mmdb"),     // Relative path
    ];

    Ok(possible_paths)
}
