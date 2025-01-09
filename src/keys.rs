use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use std::io::{self, Read};

/// Struct to hold public and private key pair
#[derive(Debug)]
pub struct KeyPair {
    pub private_key: Scalar,
    pub public_key: RistrettoPoint,
}

impl KeyPair {
    /// Generate a Schnorr signature key pair
    pub fn generate() -> KeyPair {
        let private_key: Scalar = Scalar::random(&mut OsRng);
        let public_key: RistrettoPoint = &RISTRETTO_BASEPOINT_POINT * private_key;
        return KeyPair {
            private_key,
            public_key,
        };
    }

    pub fn write_sk_to_file(&self, file_path: &str) -> Result<(), io::Error> {
        let scalar = self.private_key.to_bytes();
        let mut file = File::create(file_path)?;
        file.write_all(&scalar)?;
        return Ok(());
    }

    pub fn write_pk_to_file(&self, file_path: &str) -> Result<(), io::Error> {
        let point = self.public_key.compress().to_bytes();
        let mut file = File::create(file_path)?;
        file.write_all(&point)?;
        return Ok(());
    }

    pub fn from_file(sk_path: &str) -> Result<KeyPair, io::Error> {
        let mut file = File::open(sk_path)?;
        let mut scalar = [0u8; 32];
        file.read_exact(&mut scalar);
        let private_key = Scalar::from_bytes_mod_order(scalar);
        let public_key = &RISTRETTO_BASEPOINT_POINT * private_key;
        return Ok(KeyPair {
            private_key,
            public_key,
        });
    }

    pub fn pk_from_file(pk_path: &str) -> Result<RistrettoPoint, io::Error> {
        let mut file = File::open(pk_path)?;
        let mut point = [0u8; 32];
        file.read_exact(&mut point)?;
        let decompressed_point = CompressedRistretto(point)
            .decompress()
            .expect("Failed to decompress the point");
        return Ok(decompressed_point);
    }
}

// Unit tests for keys module
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_keypair() {
        let keypair = KeyPair::generate();
        assert!(
            keypair.public_key != RistrettoPoint::default(),
            "Public key should not be default"
        );
        assert!(
            keypair.private_key != Scalar::default(),
            "Private key should not be default"
        );
        assert!(
            keypair.private_key * &RISTRETTO_BASEPOINT_POINT == keypair.public_key,
            "Public key should be g^private_key"
        )
    }

    #[test]
    fn test_write_and_read_keypair() {
        let keypair = KeyPair::generate();
        let pk_filepath = "pk_test.txt";
        let sk_filepath = "sk_test.txt";

        // Write the keypair to a file
        keypair
            .write_sk_to_file(&sk_filepath)
            .expect("Failed to write sk to file");
        keypair
            .write_pk_to_file(&pk_filepath)
            .expect("Failed to write pk to file");

        // Read the keypair back from the file
        let read_keypair =
            KeyPair::from_file(&sk_filepath).expect("Failed to read keypair from file");

        let read_pk = KeyPair::pk_from_file(&pk_filepath).expect("Failed to read pk from file");

        // Check if the written and read key pairs are equal
        assert_eq!(
            keypair.private_key, read_keypair.private_key,
            "Private keys should match"
        );
        assert_eq!(
            keypair.public_key, read_keypair.public_key,
            "Public keys should match"
        );
        assert_eq!(keypair.public_key, read_pk, "Public keys should match");

        // Clean up the test file
        fs::remove_file(&sk_filepath).expect("Failed to remove sk test file");
        fs::remove_file(&pk_filepath).expect("Failed to remove pk test file");
    }
}
