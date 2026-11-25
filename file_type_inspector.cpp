#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <cctype>

using namespace std;

struct FileSignature {
    string name;
    string extension;
    vector<uint8_t> magicBytes;
};

const vector<FileSignature> signatures = {
    {
        "PNG Image", ".png",
        {0x89, 0x50, 0x4E, 0x47,
         0x0D, 0x0A, 0x1A, 0x0A}
    },
    {
        "JPEG Image", ".jpg",
        {0xFF, 0xD8, 0xFF}
    },
    {
        "PDF Document", ".pdf",
        {0x25, 0x50, 0x44, 0x46, 0x2D}
    },
    {
        "ZIP Archive", ".zip",
        {0x50, 0x4B, 0x03, 0x04}
    },
    {
        "ELF Executable", ".elf",
        {0x7F, 0x45, 0x4C, 0x46}
    },
    {
        "GIF Image", ".gif",
        {0x47, 0x49, 0x46, 0x38, 0x39, 0x61}
    },
    {
        "Windows PE/DOS Executable", ".exe",
        {0x4D, 0x5A}
    }
};

int main(int argc, char* argv[]) {
    // 1. Check if the user provided the file path argument
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <filename>" << endl;
        cerr << "Example: " << argv[0] << " mydata.bin" << endl;
        return 1;
    }

    // 2. Extract the file path from the command line arguments
    string filePath = argv[1];

    // 3. Open the user-specified file
    ifstream inputFile(filePath, std::ios::binary);

    if (!inputFile) {
        cerr << "Error: Could not open file '" << filePath << "'" << std::endl;
        return 1;
    }

    // Get the file size
uintmax_t fileSize = filesystem::file_size(filePath);

// Read only the first 512 bytes
vector<uint8_t> header(512);

inputFile.read(
    reinterpret_cast<char*>(header.data()),
    header.size()
);

// Keep only the bytes actually read
header.resize(inputFile.gcount());

string detectedType = "Unknown";
string expectedExtension = "";

for (const auto& sig : signatures) {

    if (header.size() >= sig.magicBytes.size()) {

        if (equal(
            sig.magicBytes.begin(),
            sig.magicBytes.end(),
            header.begin()
        )) {

            detectedType = sig.name;
            expectedExtension = sig.extension;

            break;
        }
    }
}

// Extract actual file extension
string actualExtension =
    filesystem::path(filePath).extension().string();

// Convert extension to lowercase
transform(
    actualExtension.begin(),
    actualExtension.end(),
    actualExtension.begin(),
    [](unsigned char c) {
        return static_cast<char>(tolower(c));
    }
);

// Display analysis
cout << "\nDetected Type: " << detectedType << endl;

if (detectedType == "Unknown") {
    cout << "Unknown file signature.\n";
}
else if (actualExtension != expectedExtension) {
    cout << "[WARNING] Extension mismatch!\n";
    cout << "Expected: " << expectedExtension << endl;
    cout << "Actual: " << actualExtension << endl;
}
else {
    cout << "Extension matches detected signature.\n";
}

cout << "Inspecting '" << filePath << "' (" << fileSize << " bytes):\n\n";

    // Print the first 16 bytes in hexadecimal
    size_t bytesToPrint = std::min(header.size(), static_cast<size_t>(16));
    cout << "First " << bytesToPrint << " bytes in hex:\n";

    for (size_t i = 0; i < bytesToPrint; ++i) {
        cout << std::hex << std::setw(2) << std::setfill('0') 
             << static_cast<int>(header[i]) << " ";
    }
    
    cout << dec << endl;
    return 0;
}