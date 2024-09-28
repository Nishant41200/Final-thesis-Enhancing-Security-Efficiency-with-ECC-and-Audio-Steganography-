from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import os
import sys

def encrypt_message(message_file, public_key_file, output_file):
    # Load ECC public key
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Read the message to encrypt from the file
    with open(message_file, "rb") as f:
        message = f.read()

    # Generate an ephemeral private key for this encryption
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Derive the shared secret
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive the AES key
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    )
    aes_key = hkdf.derive(shared_key)

    # Encrypt the message
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, message, None)

    # Concatenate the ephemeral public key, IV, and ciphertext
    encrypted_message = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ) + iv + ciphertext

    # Write the encrypted message to a file
    with open(output_file, "wb") as f:
        f.write(encrypted_message)

if __name__ == "__main__":
    message_file = sys.argv[1]
    public_key_file = sys.argv[2]
    output_file = sys.argv[3]
    encrypt_message(message_file, public_key_file, output_file)
