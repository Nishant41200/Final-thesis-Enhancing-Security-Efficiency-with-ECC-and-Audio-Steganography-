from pydub import AudioSegment
from gtts import gTTS
import base64
import sys

def text_to_audio(text, audio_file):
    tts = gTTS(text)
    tts.save("temp.mp3")
    audio = AudioSegment.from_mp3("temp.mp3")
    audio.export(audio_file, format="wav")

if __name__ == "__main__":
    algorithm = sys.argv[1]
    if algorithm == "rsa":
        with open("rsa_encrypted_message.bin", "rb") as file:
            encrypted_message = file.read()
        encoded_message = base64.b64encode(encrypted_message).decode()
        text_to_audio(encoded_message, "rsa_encrypted_message.wav")
    elif algorithm == "ecc":
        with open("ecc_encrypted_message.bin", "rb") as file:
            encrypted_message = file.read()
        encoded_message = base64.b64encode(encrypted_message).decode()
        text_to_audio(encoded_message, "ecc_encrypted_message.wav")
