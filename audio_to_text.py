import base64
import speech_recognition as sr
import sys

def audio_to_text(audio_file, text_file):
    recognizer = sr.Recognizer()
    with sr.AudioFile(audio_file) as source:
        audio = recognizer.record(source)
    text = recognizer.recognize_google(audio)
    decoded_message = base64.b64decode(text)
    with open(text_file, "wb") as file:
        file.write(decoded_message)

if __name__ == "__main__":
    algorithm = sys.argv[1]
    if algorithm == "rsa":
        audio_to_text("rsa_encrypted_message.wav", "rsa_extracted_message.bin")
    elif algorithm == "ecc":
        audio_to_text("ecc_encrypted_message.wav", "ecc_extracted_message.bin")
