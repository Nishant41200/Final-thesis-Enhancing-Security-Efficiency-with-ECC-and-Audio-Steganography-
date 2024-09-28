import wave
import sys

def extract_message(audio_file, output_file):
    audio = wave.open(audio_file, mode="rb")
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

    extracted_bits = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
    extracted_bytes = bytearray([int(''.join(map(str, extracted_bits[i:i + 8])), 2) for i in range(0, len(extracted_bits), 8)])
    
    message = extracted_bytes.split(b'###')[0]  # Use terminator if needed, otherwise adjust

    with open(output_file, "wb") as of:
        of.write(message)
    
    audio.close()
    print(f"Extracted message saved to {output_file}")
    print(f"Extracted message length: {len(message)} bytes")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: extract.py <audio_file> <output_file>")
        sys.exit(1)
    
    audio_file = sys.argv[1]
    output_file = sys.argv[2]
    extract_message(audio_file, output_file)
