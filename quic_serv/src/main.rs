mod cert;

use anyhow::{Error, Ok, Result};
use cert::Cert;
use rand::RngCore;
use s2n_quic::{
    provider::connection_id::{self, ConnectionInfo, Generator, LocalId, Validator},
    Server,
};

const CERT_PEM: &str = "../cert/cert.pem";
const KEY_PEM: &str = "../cert/key";

struct ConnectionIDfmt;

impl Generator for ConnectionIDfmt {
    fn generate(&mut self, _connection_info: &ConnectionInfo) -> LocalId {
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        connection_id::LocalId::try_from_bytes(&id[..]).unwrap()
    }
}

impl Validator for ConnectionIDfmt {
    fn validate(&self, _connection_info: &ConnectionInfo, _buffer: &[u8]) -> Option<usize> {
        Some(16)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    Cert::new("291123.xyz".to_string());

    let mut server = Server::builder()
        .with_tls((CERT_PEM, KEY_PEM))?
        .with_connection_id(ConnectionIDfmt)?
        .with_io("127.0.0.1:4433")?
        .start()?;

    let conn = server.accept().await;

    while let Some(ref stream) = conn {
        println!("{:?}", stream.remote_addr());
    }

    Ok(())
}
