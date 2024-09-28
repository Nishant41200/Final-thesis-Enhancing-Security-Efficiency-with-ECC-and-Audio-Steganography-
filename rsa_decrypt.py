from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import sys

def decrypt_message(encrypted_file, private_key_file, output_file):
    try:
        # Load RSA private key
        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )

        # Read the encrypted message
        with open(encrypted_file, "rb") as f:
            encrypted_message = f.read()

        # Decrypt the message
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Write the decrypted message to a file
        with open(output_file, "wb") as f:
            f.write(decrypted_message)

        print(f"RSA Decrypted Message: {decrypted_message}")
        print(f"Decrypted message length: {len(decrypted_message)} bytes")
    except Exception as e:
        print(f"Error during decryption: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python rsa_decrypt.py <encrypted_file> <private_key_file> <output_file>")
        sys.exit(1)

    encrypted_file = sys.argv[1]
    private_key_file = "rsa_private_key.pem"
    output_file = sys.argv[3]
    decrypt_message(encrypted_file, private_key_file, output_file)
