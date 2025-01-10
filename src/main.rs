mod aes;
mod elgamal;
mod hybrid_enc;
mod keys;
mod message;
mod schnorr;
mod serializers;

fn main() {
    // Load the signing key from file
    let signing_key =
        keys::KeyPair::from_file("signing_key.txt").expect("Failed to load signing key");

    // Load the encryption public key from file
    let encryption_key =
        keys::KeyPair::pk_from_file("encryption_key.txt").expect("Failed to load encryption key");

    // Create a new message containing your group ID
    let mut message = message::Message::new(
        0,
        b"Group ID: 21".to_vec(),
        signing_key.public_key.compress(),
        encryption_key.compress(),
        schnorr::SchnorrSignature::emty_signature(),
    );

    // Encrypt the message
    message
        .encrypt(&encryption_key)
        .expect("failed to encrypt the message");

    // Sign the message
    message.sign(&signing_key.private_key);

    // Serialize the message for saving
    let _ = message
        .to_file("signed_encrypted_message.json")
        .expect("Failed to save message to file");

    // Verification & decryption

    println!();
    println!("Verify message signature: {}", message.verify());

    // let decryption_key: Scalar = <load-private-key>;
    // message
    //     .decrypt(&decryption_key)
    //     .expect("Failed to decrypt message");

    // println!();
    // println!("Decrypted message:");
    // message.display();
}
