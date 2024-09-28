from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import sys

def encrypt_message(message_file, public_key_file, output_file):
    # Load RSA public key
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Read the secret message
    with open(message_file, "rb") as f:
        message = f.read()

    # Encrypt the message
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted message to a file
    with open(output_file, "wb") as f:
        f.write(encrypted_message)

    print(f"RSA Encrypted Message: {encrypted_message}")
    print(f"Encrypted message length: {len(encrypted_message)} bytes")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python rsa_encrypt.py <message_file> <output_file>")
        sys.exit(1)

    message_file = sys.argv[1]
    public_key_file = "rsa_public_key.pem"
    output_file = sys.argv[2]
    encrypt_message(message_file, public_key_file, output_file)
