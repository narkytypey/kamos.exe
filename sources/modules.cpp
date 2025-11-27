#include "utils.h"
#include "modules.h"

//token ve privilege bilgileri
void EnumTokenInfo() {
    PrintHeader("TOKEN & PRIVILEGE INFORMATION");
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "[!] OpenProcessToken failed: " << WideToString(GetErrorMessage(GetLastError()).c_str()) << "\n";
        return;
    }
    // ---- Username & SID ----
    PrintSubHeader("User Information");
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LMEM_FIXED, dwSize);

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        wchar_t szName[256], szDomain[256];
        DWORD dwName = 256, dwDomain = 256;
        SID_NAME_USE snu;

        if (LookupAccountSidW(NULL, pTokenUser->User.Sid, szName, &dwName, szDomain, &dwDomain, &snu)) {
            std::wcout << L"    Username: " << szDomain << L"\\" << szName << L"\n";
        }

        wchar_t* pSidString = NULL;
        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &pSidString)) {
            std::wcout << L"    SID: " << pSidString << L"\n";
            LocalFree(pSidString);
        }
    }
    LocalFree(pTokenUser);

    // privileges
    PrintSubHeader("Privileges");
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    PTOKEN_PRIVILEGES pPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, dwSize);

    if (GetTokenInformation(hToken, TokenPrivileges, pPrivileges, dwSize, &dwSize)) {
        std::cout << std::left << std::setw(40) << "    Privilege Name" << std::setw(15) << "Status\n";
        std::cout << "    " << std::string(55, '-') << "\n";

        for (DWORD i = 0; i < pPrivileges->PrivilegeCount; i++) {
            wchar_t pszPrivilegeName[256];
            DWORD cchPrivilegeName = ARRAYSIZE(pszPrivilegeName);

            if (LookupPrivilegeNameW(NULL, &pPrivileges->Privileges[i].Luid, pszPrivilegeName, &cchPrivilegeName)) {
                std::string privName = WideToString(pszPrivilegeName);
                std::string status = (pPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "ENABLED" : "DISABLED";
                std::cout << "    " << std::left << std::setw(40) << privName << std::setw(15) << status << "\n";
            }
        }
    }
    LocalFree(pPrivileges);

    // grup bilgileri
    PrintSubHeader("Group Membership");
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)LocalAlloc(LMEM_FIXED, dwSize);

    if (GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize)) {
        for (DWORD i = 0; i < pGroups->GroupCount; i++) {
            wchar_t szName[256], szDomain[256];
            DWORD dwName = 256, dwDomain = 256;
            SID_NAME_USE snu;

            if (LookupAccountSidW(NULL, pGroups->Groups[i].Sid, szName, &dwName, szDomain, &dwDomain, &snu)) {
                std::wcout << L"    [+] " << szDomain << L"\\" << szName;

                if (pGroups->Groups[i].Attributes & SE_GROUP_ENABLED) {
                    std::wcout << L" (ENABLED)";
                }
                std::wcout << L"\n";
            }
        }
    }
    LocalFree(pGroups);
    CloseHandle(hToken);
}

//ağ adaptörleri
void EnumNetworkAdapters() {
    PrintHeader("NETWORK ADAPTER INFORMATION");

    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;

    for (int i = 0; i < 3; i++) {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        DWORD dwRet = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);

        if (dwRet == NO_ERROR) break;
        if (dwRet != ERROR_BUFFER_OVERFLOW) {
            std::cerr << "[!] GetAdaptersAddresses failed: " << dwRet << "\n";
            return;
        }
        free(pAddresses);
        pAddresses = NULL;
    }

    if (!pAddresses) {
        std::cerr << "[!] Failed to get adapter information\n";
        return;
    }

    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    int adapterNum = 1;

    while (pCurrAddresses) {
        std::cout << "\n[Adapter " << adapterNum++ << "]\n";
        std::wcout << "    Friendly Name: " << pCurrAddresses->FriendlyName << "\n";
        std::cout << "    Description: " << WideToString(pCurrAddresses->Description) << "\n";

        // MAC adresi
        std::cout << "    MAC Address: ";
        for (UINT i = 0; i < pCurrAddresses->PhysicalAddressLength; i++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                << (int)pCurrAddresses->PhysicalAddress[i];
            if (i < pCurrAddresses->PhysicalAddressLength - 1) std::cout << "-";
        }
        std::cout << std::dec << "\n";

        // bağlı mı yoksa down mı testi
        std::cout << "    Status: ";
        switch (pCurrAddresses->OperStatus) {
        case 1: std::cout << "UP"; break;
        case 2: std::cout << "DOWN"; break;
        case 3: std::cout << "TESTING"; break;
        case 4: std::cout << "UNKNOWN"; break;
        case 5: std::cout << "DORMANT"; break;
        case 6: std::cout << "NOT PRESENT"; break;  
        case 7: std::cout << "LOWER LAYER DOWN"; break; 
        default: std::cout << "UNKNOWN (" << pCurrAddresses->OperStatus << ")"; break;
        }
        std::cout << "\n";

        // IPv4 Adresleri
        std::cout << "    IPv4 Addresses:\n";
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
        if (!pUnicast) std::cout << "      (None)\n";
        while (pUnicast) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* ipv4 = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                std::cout << "      " << inet_ntoa(ipv4->sin_addr) << "\n";
            }
            pUnicast = pUnicast->Next;
        }

        // IPv6 Adresleri
        std::cout << "    IPv6 Addresses:\n";
        pUnicast = pCurrAddresses->FirstUnicastAddress;
        if (!pUnicast) std::cout << "      (None)\n";
        bool hasIPv6 = false;
        while (pUnicast) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                hasIPv6 = true;
                sockaddr_in6* ipv6 = (sockaddr_in6*)pUnicast->Address.lpSockaddr;
                char ipv6str[46];
                InetNtopA(AF_INET6, &ipv6->sin6_addr, ipv6str, sizeof(ipv6str));
                std::cout << "      " << ipv6str << "\n";
            }
            pUnicast = pUnicast->Next;
        }
        if (!hasIPv6) std::cout << "      (None)\n";

        // DNS serverları
        std::cout << "    DNS Servers:\n";
        PIP_ADAPTER_DNS_SERVER_ADDRESS pDnsServer = pCurrAddresses->FirstDnsServerAddress;
        if (!pDnsServer) std::cout << "      (None)\n";
        while (pDnsServer) {
            if (pDnsServer->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* dns = (sockaddr_in*)pDnsServer->Address.lpSockaddr;
                std::cout << "      " << inet_ntoa(dns->sin_addr) << "\n";
            }
            else if (pDnsServer->Address.lpSockaddr->sa_family == AF_INET6) {
                sockaddr_in6* dns6 = (sockaddr_in6*)pDnsServer->Address.lpSockaddr;
                char dnsstr[46];
                InetNtopA(AF_INET6, &dns6->sin6_addr, dnsstr, sizeof(dnsstr));
                std::cout << "      " << dnsstr << "\n";
            }
            pDnsServer = pDnsServer->Next;
        }

        pCurrAddresses = pCurrAddresses->Next;
    }
    free(pAddresses);
}

// process leri listeler
std::string GetIntegrityLevel(DWORD dwIntegrity) {
    if (dwIntegrity < 0x1000) return "System";
    if (dwIntegrity < 0x2000) return "High";
    if (dwIntegrity < 0x3000) return "Medium";
    if (dwIntegrity < 0x4000) return "Low";
    return "Unknown";
}

void EnumProcesses() {
    PrintHeader("PROCESS LISTING");

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateToolhelp32Snapshot failed: " << WideToString(GetErrorMessage(GetLastError()).c_str()) << "\n";
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    std::cout << "\n" << std::left << std::setw(8) << "PID" << std::setw(8) << "PPID"
        << std::setw(45) << "Process Name" << std::setw(12) << "Integrity\n";
    std::cout << std::string(73, '-') << "\n";

    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            DWORD integrity = 0;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProc) {
                HANDLE hToken;
                if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                    DWORD dwSize = 0;
                    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
                    PTOKEN_MANDATORY_LABEL pTML = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LMEM_FIXED, dwSize);
                    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTML, dwSize, &dwSize)) {
                        DWORD* pRid = GetSidSubAuthority(pTML->Label.Sid, GetSidSubAuthorityCount(pTML->Label.Sid)[0] - 1);
                        integrity = *pRid;
                    }
                    LocalFree(pTML);
                    CloseHandle(hToken);
                }
                CloseHandle(hProc);
            }

            std::string intStr = GetIntegrityLevel(integrity);

            std::cout << std::left << std::setw(8) << pe32.th32ProcessID
                << std::setw(8) << pe32.th32ParentProcessID
                << std::setw(45) << WideToString(pe32.szExeFile)
                << std::setw(12) << intStr << "\n";

        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
}

// sistem bilgileri(os versiyonu(build vs.), çalışma zamanı, mimarisi,ram bilgisi)
void GetSystemInformation() {
    PrintHeader("SYSTEM INFORMATION");

    // makinenin adı
    PrintSubHeader("Computer Details");
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD dwSize = ARRAYSIZE(computerName);
    if (GetComputerNameW(computerName, &dwSize)) {
        std::wcout << "    Computer Name: " << computerName << "\n";
    }

    // OS Versiyonu
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    typedef NTSTATUS(WINAPI* fnRtlGetVersion)(PRTL_OSVERSIONINFOW);
    fnRtlGetVersion pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(hMod, "RtlGetVersion");

    if (pRtlGetVersion) {
        pRtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
    }
    std::cout << "    OS Version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
        << " (Build " << osvi.dwBuildNumber << ")\n";

    // hangi build versiyon bilgisi
    std::cout << "    OS Type: ";
    switch (osvi.wProductType) {
    case VER_NT_WORKSTATION: std::cout << "Workstation"; break;
    case VER_NT_SERVER: std::cout << "Server"; break;
    case VER_NT_DOMAIN_CONTROLLER: std::cout << "Domain Controller"; break;
    default: std::cout << "Unknown"; break;
    }
    std::cout << "\n";

    // cpu mimarisi, çekirdek bilgisi
    PrintSubHeader("Processor Information");
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    std::cout << "    Architecture: ";
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: std::cout << "x64"; break;
    case PROCESSOR_ARCHITECTURE_INTEL: std::cout << "x86"; break;
    case PROCESSOR_ARCHITECTURE_ARM64: std::cout << "ARM64"; break;
    default: std::cout << "Unknown"; break;
    }
    std::cout << "\n";
    std::cout << "    Processor Count: " << si.dwNumberOfProcessors << "\n";
    std::cout << "    Page Size: " << si.dwPageSize << " bytes\n";

    // ram info
    PrintSubHeader("Memory Information");
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);
    if (GlobalMemoryStatusEx(&memstat)) {
        std::cout << "    Total Physical Memory: " << (memstat.ullTotalPhys / (1024 * 1024)) << " MB\n";
        std::cout << "    Available Memory: " << (memstat.ullAvailPhys / (1024 * 1024)) << " MB\n";
        std::cout << "    Memory Load: " << memstat.dwMemoryLoad << "%\n";
    }

    // çalışma süresi
    PrintSubHeader("System Uptime");
    ULONGLONG uptime = GetTickCount64();
    ULONGLONG days = uptime / (24 * 60 * 60 * 1000);
    ULONGLONG hours = (uptime % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000);
    ULONGLONG minutes = (uptime % (60 * 60 * 1000)) / (60 * 1000);

    std::cout << "    Uptime: " << days << " days, " << hours << " hours, " << minutes << " minutes\n";
}

// dir C:\path gibi listeleme
void ListDirectory(const std::string& dirPath) {
    PrintHeader("DIRECTORY LISTING");
    std::cout << "\n[Path] " << dirPath << "\n\n";

    std::wstring wPath = StringToWide(dirPath);
    if (wPath.back() != L'\\') wPath += L'\\';
    wPath += L'*';

    WIN32_FIND_DATAW findData;
    HANDLE findHandle = FindFirstFileW(wPath.c_str(), &findData);

    if (findHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to access directory: " << WideToString(GetErrorMessage(GetLastError()).c_str()) << "\n";
        return;
    }

    std::cout << std::left << std::setw(50) << "Filename" << std::setw(15) << "Size"
        << std::setw(20) << "Type\n";
    std::cout << std::string(85, '-') << "\n";

    do {
        std::wstring filename = findData.cFileName;
        if (filename != L"." && filename != L"..") {
            std::string filesize;
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                filesize = "<DIR>";
            }
            else {
                ULONGLONG size = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                filesize = std::to_string(size) + " B";
            }

            std::cout << std::left << std::setw(50) << WideToString(filename.c_str())
                << std::setw(15) << filesize << "<FILE>\n";
        }
    } while (FindNextFileW(findHandle, &findData));

    FindClose(findHandle);
}