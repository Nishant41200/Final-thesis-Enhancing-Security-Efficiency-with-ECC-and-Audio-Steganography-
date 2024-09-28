import wave
import sys

def embed_message(message_file, audio_file, output_file):
    # Read the message from the file
    with open(message_file, "rb") as mf:
        message = mf.read()

    # Add delimiter to the message
    message += b'###'

    # Convert message to bits
    message_bits = list(map(int, ''.join([bin(byte)[2:].zfill(8) for byte in message])))

    # Read the audio file
    with wave.open(audio_file, mode="rb") as audio:
        frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

    # Check if the message is too large to fit in the audio file
    if len(message_bits) > len(frame_bytes):
        raise ValueError("Message is too large to hide in the provided audio file.")

    # Embed the message bits into the audio file's bytes
    for i, bit in enumerate(message_bits):
        frame_bytes[i] = (frame_bytes[i] & 254) | bit

    # Write the modified frames to a new audio file
    with wave.open(output_file, "wb") as new_audio:
        new_audio.setparams(audio.getparams())
        new_audio.writeframes(bytes(frame_bytes))

    print(f"Message embedded into {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: embed.py <message_file> <audio_file> <output_file>")
        sys.exit(1)

    message_file = sys.argv[1]
    audio_file = sys.argv[2]
    output_file = sys.argv[3]
    embed_message(message_file, audio_file, output_file)
