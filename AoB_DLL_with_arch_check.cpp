#include <windows.h>
#include <psapi.h> // Fixed: Necessary header for module info tracking
#include <vector>
#include <iostream>

#pragma comment(lib, "psapi.lib")

struct PatternByte {
    BYTE value;
    bool isWildcard;
};

// Utility function to detect process architecture
bool IsProcess64Bit() {
#ifdef _WIN64
    return true;
#else
    return false;
#endif
}

// Alternative runtime detection for mixed architecture support
bool IsProcess64BitRuntime() {
    BOOL isWow64 = FALSE;
    HANDLE hProcess = GetCurrentProcess();
    
    if (!IsWow64Process(hProcess, &isWow64)) {
        return IsProcess64Bit(); // Fallback to compile-time detection
    }
    
    // If running on 64-bit OS but process is 32-bit, isWow64 will be TRUE
    // If running 64-bit process on 64-bit OS, isWow64 will be FALSE
    return !isWow64 || IsProcess64Bit();
}

// Thread-safe pattern parsing algorithm
std::vector<PatternByte> ParsePattern(const char* patternStr) {
    std::vector<PatternByte> parsed;
    while (*patternStr) {
        if (*patternStr == ' ') {
            patternStr++;
            continue;
        }
        if (*patternStr == '?') {
            parsed.push_back({ 0, true });
            patternStr += (*(patternStr + 1) == '?') ? 2 : 1;
        } else {
            parsed.push_back({ (BYTE)strtol(patternStr, nullptr, 16), false });
            patternStr += 2;
        }
    }
    return parsed;
}

// Fixed Emulator Module Scan: Checks entire committed memory blocks safely
BYTE* RobustInternalScan(const char* patternStr) {
    std::vector<PatternByte> pattern = ParsePattern(patternStr);
    size_t patternLen = pattern.size();
    if (patternLen == 0) return nullptr;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    BYTE* currentAddress = reinterpret_cast<BYTE*>(si.lpMinimumApplicationAddress);
    BYTE* maxAddress = reinterpret_cast<BYTE*>(si.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi;

    // Iterate through all memory regions to account for emulator private heap spaces
    while (currentAddress < maxAddress) {
        if (VirtualQuery(currentAddress, &mbi, sizeof(mbi))) {
            // Only scan memory sections that are committed and readable
            if (mbi.State == MEM_COMMIT && 
               (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ))) {
                
                BYTE* startAddress = reinterpret_cast<BYTE*>(mbi.BaseAddress);
                size_t searchSize = mbi.RegionSize;

                if (searchSize >= patternLen) {
                    for (size_t i = 0; i <= searchSize - patternLen; ++i) {
                        bool match = true;
                        for (size_t j = 0; j < patternLen; ++j) {
                            if (!pattern[j].isWildcard && startAddress[i + j] != pattern[j].value) {
                                match = false;
                                break;
                            }
                        }
                        if (match) {
                            return &startAddress[i]; // Found target structure base address
                        }
                    }
                }
            }
            // Move pointer forward past the currently scanned allocation region
            currentAddress += mbi.RegionSize;
        } else {
            currentAddress += 4096; // Avoid infinite stalls on access violations
        }
    }
    return nullptr;
}

// Safely transforms structure properties via direct pointer manipulation
void ProcessMemorySwap(BYTE* foundAoB) {
    const size_t prefixOffset = 88;   // Fixed Bug: Recalculated exact index offset
    const size_t wildcardLength = 32; // Exact count of '??' wildcards

    BYTE* targetWindow = foundAoB + prefixOffset;
    DWORD oldProtect;

    // Override memory page protection flags locally
    if (VirtualProtect(targetWindow, wildcardLength, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        
        for (size_t i = 0; i < wildcardLength; ++i) {
            if (targetWindow[i] == 0xB8) {
                targetWindow[i] = 0xB4; // Inline atomic hardware value update
            }
        }

        // Restore baseline OS permission tracking state
        VirtualProtect(targetWindow, wildcardLength, oldProtect, &oldProtect);
    }
}

DWORD WINAPI MainCheatThread(LPVOID lpParam) {
    // Architecture check: Validate process bitness before pattern scanning
    bool is64Bit = IsProcess64BitRuntime();
    
    // Define patterns for different architectures
    const char* targetAoB_32bit = 
        "FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00[...]";
    
    const char* targetAoB_64bit = 
        "FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00[...]";
    
    // Select appropriate pattern based on architecture
    const char* targetAoB = is64Bit ? targetAoB_64bit : targetAoB_32bit;

    // Perform an omnidirectional system address scan
    BYTE* matchedLocation = RobustInternalScan(targetAoB);

    if (matchedLocation != nullptr) {
        ProcessMemorySwap(matchedLocation);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, MainCheatThread, NULL, 0, NULL);
    }
    return TRUE;
}
