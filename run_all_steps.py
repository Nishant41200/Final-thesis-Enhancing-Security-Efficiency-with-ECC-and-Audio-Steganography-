import subprocess
import os

def run_command(command):
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if result.returncode != 0:
        print(f"Error running command: {command}\n{result.stderr}")
        return False, result.stderr
    else:
        print(f"Command executed successfully: {command}\n{result.stdout}")
        return True, result.stdout

def verify_file_exists(file_path):
    if os.path.exists(file_path):
        print(f"File exists: {file_path}")
        return True
    else:
        print(f"File does not exist: {file_path}")
        return False

# Step 1: Key Generation
command = "python key_gen.py"
success, output = run_command(command)
if not success:
    exit()

# Verify key files
key_files = ["rsa_public_key.pem", "rsa_private_key.pem", "ecc_public_key.pem", "ecc_private_key.pem"]
for key_file in key_files:
    if not verify_file_exists(key_file):
        exit()

# Step 2: RSA Encryption
command = "python rsa_encrypt.py"
success, output = run_command(command)
if not success:
    exit()

# Verify RSA encrypted message
if not verify_file_exists("rsa_encrypted_message.bin"):
    exit()

# Step 3: ECC Encryption
command = "python ecc_encrypt.py"
success, output = run_command(command)
if not success:
    exit()

# Verify ECC encrypted message
if not verify_file_exists("ecc_encrypted_message.bin"):
    exit()

# Step 4: Embedding RSA Encrypted Message
command = "python embed.py rsa_encrypted_message.bin secret_audio.wav rsa_embedded_audio.wav"
success, output = run_command(command)
if not success:
    exit()

# Verify RSA embedded audio
if not verify_file_exists("rsa_embedded_audio.wav"):
    exit()

# Step 5: Embedding ECC Encrypted Message
command = "python embed.py ecc_encrypted_message.bin secret_audio.wav ecc_embedded_audio.wav"
success, output = run_command(command)
if not success:
    exit()

# Verify ECC embedded audio
if not verify_file_exists("ecc_embedded_audio.wav"):
    exit()

# Step 6: Extracting RSA Encrypted Message
command = "python extract.py rsa_embedded_audio.wav rsa_extracted_message.bin"
success, output = run_command(command)
if not success:
    exit()

# Verify RSA extracted message
if not verify_file_exists("rsa_extracted_message.bin"):
    exit()

# Step 7: Extracting ECC Encrypted Message
command = "python extract.py ecc_embedded_audio.wav ecc_extracted_message.bin"
success, output = run_command(command)
if not success:
    exit()

# Verify ECC extracted message
if not verify_file_exists("ecc_extracted_message.bin"):
    exit()

# Step 8: Decrypting RSA Extracted Message
command = "python rsa_decrypt.py"
success, output = run_command(command)
if not success:
    exit()

# Step 9: Decrypting ECC Extracted Message
command = "python ecc_decrypt.py"
success, output = run_command(command)
if not success:
    exit()
