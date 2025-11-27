#include "utils.h"
#include "modules.h"

void PrintUsage() {
    std::cout << "\n" << std::string(70, '=') << "\n";
    std::cout << "  NCRT v1.0 - No-Child-Process Recon Tool\n";
    std::cout << "  Authorized Penetration Testing Only\n";
    std::cout << std::string(70, '=') << "\n";
    std::cout << "\nUsage:\n";
    std::cout << "  NCRT.exe tokeninfo   - Token and privilege information\n";
    std::cout << "  NCRT.exe network     - Network adapter configuration\n";
    std::cout << "  NCRT.exe proclist    - Process listing with integrity levels\n";
    std::cout << "  NCRT.exe sysinfo     - System information\n";
    std::cout << "  NCRT.exe dir <path>  - Directory listing\n";
    std::cout << "  NCRT.exe all         - Execute all reconnaissance modules\n";
    std::cout << "\nExample:\n";
    std::cout << "  NCRT.exe all\n";
    std::cout << "  NCRT.exe dir C:\\\\Users\\\n";
    std::cout << std::string(70, '=') << "\n\n";
}

int main(int argc, char* argv[]) {
    PrintUsage();

    if (argc < 2) {
        std::cerr << "[!] Missing command. Use 'all' for comprehensive recon.\n";
        return 1;
    }

    std::string command = argv[1];
    std::transform(command.begin(), command.end(), command.begin(), ::tolower);

    try {
        if (command == "tokeninfo") {
            EnumTokenInfo();
        }
        else if (command == "network") {
            EnumNetworkAdapters();
        }
        else if (command == "proclist") {
            EnumProcesses();
        }
        else if (command == "sysinfo") {
            GetSystemInformation();
        }
        else if (command == "dir") {
            if (argc < 3) {
                std::cerr << "[!] Please specify a directory path.\n";
                return 1;
            }
            ListDirectory(argv[2]);
        }
        else if (command == "all") {
            EnumTokenInfo();
            EnumNetworkAdapters();
            EnumProcesses();
            GetSystemInformation();
            ListDirectory("C:\\");
        }
        else {
            std::cerr << "[!] Unknown command: " << command << "\n";
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\n[+] Reconnaissance complete.\n";
    return 0;
}