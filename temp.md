To solve **Challenges 6 and 7** based on your provided code, we need to implement the methods in the `Message` struct for encryption, decryption, signing, and verification. 

Here's the completed code for the `Message` struct in the `src/message.rs` file that fulfills the requirements of both challenges.

### Modifications in `src/message.rs`

```rust
use crate::hybrid_enc::HybridCiphertext;
use crate::keys::KeyPair;
use crate::schnorr::{SchnorrSignature, emty_signature};
use crate::serializers::*;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::{self, Read};

// All other struct and imports remain unchanged

impl Message {
    /// Creates a new message with a version, payload, and recipient (CompressedRistretto converted to Vec<u8>)
    pub fn new(
        version: u8,
        payload: Vec<u8>,
        sender: CompressedRistretto,
        recipient: CompressedRistretto,
        signature: SchnorrSignature,
    ) -> Self {
        Self {
            version,
            payload,
            sender: sender.to_bytes(),
            recipient: recipient.to_bytes(),
            signature,
        }
    }

    /// Writes the message to a JSON file
    pub fn to_file(&self, filepath: &str) -> std::io::Result<()> {
        let file = File::create(filepath)?;
        serde_json::to_writer_pretty(file, &self)?;
        Ok(())
    }

    /// Encrypts the whole message using hybrid encryption
    pub fn encrypt(&mut self, elgamal_public_key: &RistrettoPoint) -> Result<(), String> {
        // Serialize the current message excluding the signature and other fields
        let serialized_message = serialize_message_to_bytes(self)?;
        let hybrid_ciphertext = HybridCiphertext::encrypt(&serialized_message, elgamal_public_key)?;

        // Update the message payload to contain the encrypted data
        self.payload = hybrid_ciphertext.serialize(); // Store as bytes

        // Update other fields
        self.version += 1;
        self.sender = [0u8; 32]; // Set to default sender
        self.recipient = elgamal_public_key.compress().to_bytes(); // Update with recipient's public key
        self.signature = emty_signature(); // Clear signature after encryption
        
        Ok(())
    }

    /// Decrypts the payload using hybrid decryption, sets version back to 0
    pub fn decrypt(&mut self, elgamal_private_key: &Scalar) -> Result<(), String> {
        let hybrid_ciphertext = HybridCiphertext::deserialize(&self.payload)?;
        let decrypted_bytes = hybrid_ciphertext.decrypt(elgamal_private_key)?;

        // Deserialize the original message from bytes
        let decrypted_message = deserialize_message_from_bytes(&decrypted_bytes)?;
        self.version = decrypted_message.version;
        self.payload = decrypted_message.payload;
        self.sender = decrypted_message.sender;
        self.recipient = decrypted_message.recipient;
        self.signature = decrypted_message.signature;

        Ok(())
    }

    /// Signs the payload using Schnorr signatures, sets the signing public key as sender
    pub fn sign(&mut self, signing_key: &Scalar) {
        let vk = signing_key * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        // Sign the payload
        let signature = SchnorrSignature::sign(&self.payload, signing_key);

        self.signature = signature; // Save the signature
        self.sender = vk.compress().to_bytes(); // Set the sender to the public key
    }

    /// Verifies the signature
    pub fn verify(&self) -> bool {
        let vk = RistrettoPoint::from_bytes(&self.sender).expect("Invalid sender format");
        SchnorrSignature::verify(&self.signature, &self.payload, &vk)
    }
}
```

### Implementation Breakdown:

1. **new()**: Initializes a new `Message` with the provided parameters. Converts `CompressedRistretto` to bytes for `sender` and `recipient`.

2. **to_file()**: Serializes the `Message` to a JSON file.

3. **encrypt()**: 
    - Serializes the message (payload, sender, recipient, but not the signature).
    - Uses the `HybridCiphertext` to encrypt the serialized bytes and stores the result in `self.payload`.
    - Updates `version`, resets `sender`, sets `recipient`, and clears the signature.

4. **decrypt()**: 
    - Deserializes the `payload` to obtain the hybrid ciphertext.
    - Decrypts the encrypted message and updates the fields of the `Message` struct to reflect the original data.

5. **sign()**: 
    - Signs the message payload using the provided signing key and updates the `signature` field.
    - Sets the sender's compressed public key.

6. **verify()**: 
   - Verifies the signature against the payload and reports the validity.

### Main Function Implementation for Challenge 7

Now, let's implement the main function in `src/main.rs` using the provided instructions for Challenge 7.

```rust
fn main() {
    // Load the signing key from file
    let signing_key = KeyPair::from_file("signing_key.txt").expect("Failed to load signing key");

    // Load the encryption public key from file
    let encryption_key = KeyPair::pk_from_file("encryption_key.txt").expect("Failed to load encryption key");

    // Create a new message containing your group ID
    let mut message = Message::new(1, b"Group ID: 123456".to_vec(), 
                                    signing_key.public_key.compress(), 
                                    encryption_key.compress(), 
                                    emty_signature());

    // Encrypt the message
    message.encrypt(&encryption_key).expect("failed to encrypt the message");

    // Sign the message
    message.sign(&signing_key.private_key);

    // Serialize the message for saving
    let _ = message.to_file("signed_encrypted_message.json").expect("Failed to save message to file");
}
```

### Summary

1. The provided code implements the complete functionality required for managing messages securely through encryption, signing, and deserialization.
2. Challenge 6 is addressed by implementing the `Message` struct with necessary methods, while Challenge 7 provides a complete workflow for loading keys, creating a message, encrypting, signing, and storing it as JSON.





---
---
---
To run your Rust project, follow these steps to compile and execute your code:

### 1. Ensure You Have Rust Installed
Check that you have Rust installed by running:
```bash
rustc --version
```
If Rust is not installed, you can install it using [rustup](https://rustup.rs/).

### 2. Create Project Structure (if not already done)
Make sure you have the following project structure:
```
Exercise2/
├── Cargo.toml
└── src/
    ├── aes.rs
    ├── elgamal.rs
    ├── hybrid_enc.rs
    ├── keys.rs
    ├── main.rs
    ├── message.rs
    ├── schnorr.rs
    ├── serializers.rs
    └── tests.rs
```

### 3. Add Required Files
Ensure you have added the necessary key files: 
- `signing_key.txt`: Contains the private key for signing.
- `encryption_key.txt`: Contains the public key for encryption.
- `signed_encrypted_message.json`: This is the output file for your encrypted message.

Make sure these files are in the root of your project folder (`Exercise2`).

### 4. Performance Dependencies 
Make sure you have all dependencies included in your `Cargo.toml` as you've specified.

### 5. Run the Main Program
To compile and run the program, navigate to your project directory in your terminal. Then run the following command:

**For Linux/Mac:**
```bash
cd path/to/Exercise2
cargo run
```

**For Windows:**
```bash
cd path\to\Exercise2
cargo run
```

### 6. Check Output File
After successful execution, check for the `signed_encrypted_message.json` file in your project directory. This file should now contain your encrypted and signed message.

### 7. Unit Tests (Optional)
If you want to run the unit tests included in your code to ensure everything works correctly, you can run:
```bash
cargo test
```
This will execute all tests present in the `src/tests.rs` file and any associated tests in other source files.

### Summary
Creating a script isn't usually needed for a Rust project given that most of the operations are handled by Cargo. Just ensure you have your project structured properly, dependencies met, and the required key files available. Following the steps above will get your project up and running successfully!