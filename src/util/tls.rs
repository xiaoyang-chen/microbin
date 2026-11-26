use crate::args::ARGS;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::fs;
use std::io;
#[cfg(unix)]
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";
const SELF_SIGNED_VALID_DAYS: u32 = 36500; // 100 years

pub fn acceptor_builder() -> io::Result<SslAcceptorBuilder> {
    let (certs, key) = load_or_generate()?;

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(ssl_error)?;
    acceptor.set_certificate(&certs[0]).map_err(ssl_error)?;
    for cert in &certs[1..] {
        acceptor
            .add_extra_chain_cert(cert.clone())
            .map_err(ssl_error)?;
    }
    acceptor.set_private_key(&key).map_err(ssl_error)?;
    acceptor.check_private_key().map_err(ssl_error)?;
    Ok(acceptor)
}

fn load_or_generate() -> io::Result<(Vec<X509>, PKey<Private>)> {
    match (ARGS.tls_cert_path(), ARGS.tls_key_path()) {
        (Some(cert), Some(key)) => {
            log::info!("HTTPS enabled with configured certificate {cert} and key {key}");
            load_pair(Path::new(cert), Path::new(key))
        }
        (None, None) => {
            let dir = Path::new(&ARGS.data_dir).join("tls");
            let cert_path = dir.join(CERT_FILE);
            let key_path = dir.join(KEY_FILE);
            if cert_path.is_file() && key_path.is_file() {
                match load_pair(&cert_path, &key_path) {
                    Ok(pair) => {
                        log::info!(
                            "HTTPS enabled with self-signed certificate {}",
                            cert_path.display()
                        );
                        return Ok(pair);
                    }
                    Err(error) => log::warn!(
                        "Could not load the existing self-signed certificate ({}). Generating a new one.",
                        error
                    ),
                }
            }
            generate_self_signed(&dir, &cert_path, &key_path)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--tls-cert and --tls-key must be configured together",
        )),
    }
}

fn load_pair(
    cert_path: &Path,
    key_path: &Path,
) -> io::Result<(Vec<X509>, PKey<Private>)> {
    let cert_pem = fs::read(cert_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to read TLS certificate {}: {error}",
                cert_path.display()
            ),
        )
    })?;
    let certs = X509::stack_from_pem(&cert_pem).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse TLS certificate {}: {error}",
                cert_path.display()
            ),
        )
    })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TLS certificate {} does not contain any certificate",
                cert_path.display()
            ),
        ));
    }

    let key_pem = fs::read(key_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to read TLS private key {}: {error}",
                key_path.display()
            ),
        )
    })?;
    let key = PKey::private_key_from_pem(&key_pem).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse TLS private key {}: {error}",
                key_path.display()
            ),
        )
    })?;

    Ok((certs, key))
}

fn generate_self_signed(
    dir: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> io::Result<(Vec<X509>, PKey<Private>)> {
    fs::create_dir_all(dir).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to create TLS directory {}: {error}",
                dir.display()
            ),
        )
    })?;

    let rsa = Rsa::generate(2048).map_err(ssl_error)?;
    let key = PKey::from_rsa(rsa).map_err(ssl_error)?;

    let (dns_names, ip_addresses) = certificate_names();
    let common_name = dns_names
        .first()
        .cloned()
        .or_else(|| ip_addresses.first().map(ToString::to_string))
        .unwrap_or_else(|| String::from("localhost"));

    let mut name = X509NameBuilder::new().map_err(ssl_error)?;
    name.append_entry_by_nid(Nid::COMMONNAME, &common_name)
        .map_err(ssl_error)?;
    let name = name.build();

    let mut builder = X509::builder().map_err(ssl_error)?;
    builder.set_version(2).map_err(ssl_error)?;
    let serial_bn = random_serial()?;
    let serial_asn1 = serial_bn.to_asn1_integer().map_err(ssl_error)?;
    builder.set_serial_number(&serial_asn1).map_err(ssl_error)?;
    builder.set_subject_name(&name).map_err(ssl_error)?;
    builder.set_issuer_name(&name).map_err(ssl_error)?;
    builder.set_pubkey(&key).map_err(ssl_error)?;

    let not_before = Asn1Time::days_from_now(0).map_err(ssl_error)?;
    let not_after = Asn1Time::days_from_now(SELF_SIGNED_VALID_DAYS).map_err(ssl_error)?;
    builder.set_not_before(&not_before).map_err(ssl_error)?;
    builder.set_not_after(&not_after).map_err(ssl_error)?;

    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .map_err(ssl_error)?,
        )
        .map_err(ssl_error)?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .key_cert_sign()
                .build()
                .map_err(ssl_error)?,
        )
        .map_err(ssl_error)?;
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .server_auth()
                .build()
                .map_err(ssl_error)?,
        )
        .map_err(ssl_error)?;
    builder
        .append_extension(build_subject_alt_name(
            &builder,
            &dns_names,
            &ip_addresses,
        )?)
        .map_err(ssl_error)?;

    builder.sign(&key, MessageDigest::sha256()).map_err(ssl_error)?;
    let cert = builder.build();

    let cert_pem = cert.to_pem().map_err(ssl_error)?;
    let key_pem = key.private_key_to_pem_pkcs8().map_err(ssl_error)?;
    fs::write(cert_path, cert_pem)?;
    write_private_key(key_path, &key_pem)?;

    log::warn!(
        "No TLS certificate configured; generated a self-signed certificate for {}. \
         It is valid for 100 years and will be reused on the next start. Browsers will warn until you trust it.",
        cert_path.display()
    );

    Ok((vec![cert], key))
}

fn build_subject_alt_name(
    builder: &X509Builder,
    dns_names: &[String],
    ip_addresses: &[IpAddr],
) -> io::Result<openssl::x509::X509Extension> {
    let mut san = SubjectAlternativeName::new();
    for dns_name in dns_names {
        san.dns(dns_name);
    }
    for ip_address in ip_addresses {
        san.ip(&ip_address.to_string());
    }
    let context = builder.x509v3_context(None, None);
    san.build(&context).map_err(ssl_error)
}

fn certificate_names() -> (Vec<String>, Vec<IpAddr>) {
    let mut dns_names = Vec::new();
    let mut ip_addresses = Vec::new();

    for public_path in [ARGS.public_path.as_ref(), ARGS.short_path.as_ref()]
        .into_iter()
        .flatten()
    {
        add_host(&public_path.0, &mut dns_names, &mut ip_addresses);
    }

    if !dns_names.iter().any(|name| name.as_str() == "localhost") {
        dns_names.push(String::from("localhost"));
    }
    for ip in ["127.0.0.1", "::1"] {
        let ip = ip.parse::<IpAddr>().expect("valid loopback address");
        if !ip_addresses.contains(&ip) {
            ip_addresses.push(ip);
        }
    }

    let bind_is_unspecified = match ARGS.bind {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_unspecified(),
    };
    if !bind_is_unspecified && !ip_addresses.contains(&ARGS.bind) {
        ip_addresses.push(ARGS.bind);
    }

    (dns_names, ip_addresses)
}

fn add_host(value: &str, dns_names: &mut Vec<String>, ip_addresses: &mut Vec<IpAddr>) {
    let Some(host) = host_from_url(value) else {
        return;
    };
    match host.parse::<IpAddr>() {
        Ok(ip) => {
            if !ip_addresses.contains(&ip) {
                ip_addresses.push(ip);
            }
        }
        Err(_) => {
            if !dns_names.contains(&host) {
                dns_names.push(host);
            }
        }
    }
}

fn host_from_url(value: &str) -> Option<String> {
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value)
        .split('/')
        .next()?
        .trim();
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        return rest
            .split(']')
            .next()
            .filter(|host| !host.is_empty())
            .map(str::to_owned);
    }
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn random_serial() -> io::Result<BigNum> {
    let mut bytes = rand::random::<u128>().to_be_bytes();
    bytes[0] &= 0x7f;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[15] = 1;
    }
    BigNum::from_slice(&bytes).map_err(ssl_error)
}

#[cfg(unix)]
fn write_private_key(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn write_private_key(path: &Path, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)
}

fn ssl_error(error: openssl::error::ErrorStack) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}
