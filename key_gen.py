from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Generate RSA keys
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
rsa_public_key = rsa_private_key.public_key()

# Generate ECC keys
ecc_private_key = ec.generate_private_key(ec.SECP256R1())
ecc_public_key = ecc_private_key.public_key()

# Save RSA keys
with open("rsa_private_key.pem", "wb") as f:
    f.write(rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("rsa_public_key.pem", "wb") as f:
    f.write(rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Save ECC keys
with open("ecc_private_key.pem", "wb") as f:
    f.write(ecc_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("ecc_public_key.pem", "wb") as f:
    f.write(ecc_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("RSA and ECC keys generated successfully.")
