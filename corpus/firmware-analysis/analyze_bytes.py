
from collections import Counter
import math

with open('03_graphics_acceleration.bin', 'rb') as f:
    data = f.read()

print(f"Total size: {len(data)} bytes")
print(f"\nByte distribution:")
counter = Counter(data)
print(f"  Zero bytes: {counter[0]} ({counter[0]/len(data)*100:.1f}%)")
print(f"  0xFF bytes: {counter[0xFF]} ({counter[0xFF]/len(data)*100:.1f}%)")
print(f"  Unique byte values: {len(counter)}/256")

# Entropy per 1KB chunk
print(f"\nEntropy by 1KB chunk:")
for i in range(0, len(data), 1024):
    chunk = data[i:i+1024]
    if len(chunk) < 1024:
        break

    # Calculate entropy
    counter = Counter(chunk)
    entropy = 0
    for count in counter.values():
        p = count / len(chunk)
        entropy -= p * math.log2(p)

    # Check if mostly zeros
    zero_pct = counter[0] / len(chunk) * 100

    status = "EMPTY" if zero_pct > 80 else "DATA" if entropy > 4 else "LOW"
    print(f"  Chunk {i//1024:3d} (0x{i:05x}): entropy={entropy:.2f}, zeros={zero_pct:5.1f}% [{status}]")
