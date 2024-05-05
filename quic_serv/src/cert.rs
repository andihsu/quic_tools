use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

const CERT_PEM: &str = "./cert/cert.pem";
const KEY_PEM: &str = "./cert/key";

pub struct Cert;

impl Cert {
    pub fn new(domain: String) {
        let (folder_state, (cert_state, key_state)) = Self::check_state();

        if !folder_state {
            fs::create_dir(Path::new("cert")).unwrap();
        }

        if cert_state && key_state {
            // Clear files.
            fs::remove_file(Path::new(CERT_PEM)).unwrap();
            fs::remove_file(Path::new(KEY_PEM)).unwrap();
        }

        let mut cert_file = File::create(Path::new(CERT_PEM)).unwrap();
        let mut key_file = File::create(Path::new(KEY_PEM)).unwrap();

        let (cert_pem, key) = Self::gen_certs(domain);

        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        key_file.write_all(key.as_bytes()).unwrap();
    }

    fn check_state() -> (bool, (bool, bool)) {
        let folder_state = match Path::new("./cert").try_exists() {
            Ok(state) => state,
            Err(_) => false,
        };

        let cert_state = match Path::new("./cert/cert.pem").try_exists() {
            Ok(state) => state,
            Err(_) => false,
        };

        let key_state = match Path::new("./cert/key").try_exists() {
            Ok(state) => state,
            Err(_) => false,
        };
        (folder_state, (cert_state, key_state))
    }

    fn gen_certs(domain: String) -> (String, String) {
        let subject_alt_name = vec![domain, "localhost".to_string()];
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(subject_alt_name).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }
}
