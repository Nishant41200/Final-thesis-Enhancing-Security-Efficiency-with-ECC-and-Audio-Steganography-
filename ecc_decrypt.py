from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys

def decrypt_message(encrypted_file, private_key_file, output_file):
    try:
        # Load the private key
        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        # Read the encrypted message
        with open(encrypted_file, "rb") as f:
            encrypted_message = f.read()

        # Extract the ephemeral public key, IV, and ciphertext
        ephemeral_public_key_bytes = encrypted_message[:65]
        iv = encrypted_message[65:77]
        ciphertext = encrypted_message[77:]

        print(f"Ephemeral public key bytes: {ephemeral_public_key_bytes}")
        print(f"IV: {iv}")
        print(f"Ciphertext: {ciphertext}")

        # Convert ephemeral public key bytes to a public key object
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_public_key_bytes)

        # Perform the key exchange
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # Derive the AES key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)

        print(f"Derived key: {derived_key}")

        # Decrypt the message
        aesgcm = AESGCM(derived_key)
        decrypted_message = aesgcm.decrypt(iv, ciphertext, None)

        # Write the decrypted message to a file
        with open(output_file, "wb") as f:
            f.write(decrypted_message)

        print(f"ECC Decrypted Message: {decrypted_message.decode()}")

    except Exception as e:
        print(f"Error during decryption: {e}")

if __name__ == "__main__":
    encrypted_file = sys.argv[1]
    private_key_file = sys.argv[2]
    output_file = sys.argv[3]
    decrypt_message(encrypted_file, private_key_file, output_file)
