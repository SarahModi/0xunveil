# 0xunveil

**A lightweight C++20 binary header inspector, magic-byte file signature identifier, and extension-spoofing detector.**

`0xunveil` reads the first 512 bytes of any target file to identify its true format via magic-byte signatures, displays a hexadecimal header dump, and alerts you when a file's extension does not match its underlying binary structure (**MITRE ATT&CK T1036: Masquerading**).

---

## Key Features
* **Constant-Memory Header Inspection:** Reads only the first 512 bytes using `std::ifstream::read()` instead of loading entire files into RAM—allowing safe, fast inspection of multi-gigabyte files.
* **Magic-Byte Signature Identification:** Detects common binary formats directly from file headers:
  * Windows PE/DOS Executables (`.exe` — `4D 5A`)
  * Linux ELF Executables (`.elf` — `7F 45 4C 46`)
  * PDF Documents (`.pdf` — `25 50 44 46 2D`)
  * PNG Images (`.png` — `89 50 4E 47 0D 0A 1A 0A`)
  * JPEG Images (`.jpg` — `FF D8 FF`)
  * GIF Images (`.gif` — `47 49 46 38 39 61`)
  * ZIP Archives (`.zip` — `50 4B 03 04`)
* **Extension Spoofing Detection:** Extracts and normalizes the target file's extension via `std::filesystem` and flags mismatches against its true magic-byte signature (e.g., an `.exe` disguised as `.pdf`).
* **Hexadecimal Header Dump:** Prints the first 16 bytes of the file in clean, zero-padded hex alongside total file size.

---

## Build & Usage

### Prerequisites
* A C++17 / C++20 compatible compiler (`g++`, `clang++`, or MSVC) with `<filesystem>` support.

### Compile
```bash
g++ -std=c++20 -O2 -Wall -Wextra 0xunveil.cpp -o 0xunveil
```

### Run
```bash
./0xunveil <filename>
```

---

## Example Output

### 1. Exposing a Disguised Executable (`invoice.pdf`)
```text
\$ ./0xunveil invoice.pdf

Detected Type: Windows PE/DOS Executable
[WARNING] Extension mismatch!
Expected: .exe
Actual: .pdf
Inspecting 'invoice.pdf' (80185 bytes):

First 16 bytes in hex:
4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00
```

### 2. Verifying a Legitimate File (`IMG_9732.JPG`)
```text
\$ ./0xunveil IMG_9732.JPG

Detected Type: JPEG Image
Extension matches detected signature.
Inspecting 'IMG_9732.JPG' (2996936 bytes):

First 16 bytes in hex:
ff d8 ff e0 00 14 4a 46 49 46 00 01 01 01 01 2c
```

---

## Disclaimer
Built for educational purposes, malware triage practice, and authorized security analysis.
