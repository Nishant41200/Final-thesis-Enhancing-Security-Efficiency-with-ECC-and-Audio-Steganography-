import os
import subprocess

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {command}")
        print(result.stderr)
    else:
        print(f"Command executed successfully: {command}")
        print(result.stdout)

commands = [
    "python key_gen.py",
    "python rsa_encrypt.py",
    "python ecc_encrypt.py",
    "python embed.py rsa_encrypted_message.bin secret_audio.wav rsa_embedded_audio.wav",
    "python embed.py ecc_encrypted_message.bin secret_audio.wav ecc_embedded_audio.wav",
    "python extract.py rsa_embedded_audio.wav rsa_extracted_message.bin",
    "python extract.py ecc_embedded_audio.wav ecc_extracted_message.bin",
    "python rsa_decrypt.py",
    "python ecc_decrypt.py"
]

for command in commands:
    run_command(command)
