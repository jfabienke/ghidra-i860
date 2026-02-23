
import sys
import math
import os

def analyze_bytes(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return

    size = len(data)
    if size == 0:
        print("File is empty.")
        return

    print(f"Total size: {size} bytes")
    
    # Byte distribution
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    zero_bytes = byte_counts[0]
    ff_bytes = byte_counts[255]
    unique_bytes = len([count for count in byte_counts if count > 0])

    print("\nByte distribution:")
    print(f"  Zero bytes: {zero_bytes} ({zero_bytes / size:.1%})")
    print(f"  0xFF bytes: {ff_bytes} ({ff_bytes / size:.1%})")
    print(f"  Unique byte values: {unique_bytes}/256")

    # Entropy calculation
    print("\nEntropy by 1KB chunk:")
    chunk_size = 1024
    num_chunks = math.ceil(size / chunk_size)

    for i in range(num_chunks):
        start = i * chunk_size
        end = start + chunk_size
        chunk = data[start:end]
        
        if not chunk:
            continue

        chunk_entropy = 0
        chunk_len = len(chunk)
        byte_freq = [0] * 256
        for byte in chunk:
            byte_freq[byte] += 1

        for count in byte_freq:
            if count > 0:
                prob = count / chunk_len
                chunk_entropy -= prob * math.log2(prob)
        
        zero_percentage = byte_freq[0] / chunk_len
        
        status = "DATA"
        if chunk_entropy < 2.0:
            status = "EMPTY"
        elif chunk_entropy < 5.0:
            status = "LOW"

        print(f"  Chunk {i:3d} (0x{start:05x}): entropy={chunk_entropy:.2f}, zeros={zero_percentage:6.1%} [{status}]")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <file_path>")
    else:
        analyze_bytes(sys.argv[1])
