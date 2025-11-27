#include "utils.h"

std::wstring GetErrorMessage(DWORD error) {
    wchar_t buf[256];
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, buf, sizeof(buf) / sizeof(buf[0]), NULL);
    return std::wstring(buf);
}

std::string WideToString(const wchar_t* wide) {
    if (!wide) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    std::string str(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &str[0], size, NULL, NULL);
    return str;
}

std::wstring StringToWide(const std::string& str) {
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size);
    return wstr;
}

void PrintHeader(const std::string& title) {
    std::cout << "\n" << std::string(70, '=') << "\n";
    std::cout << "  " << title << "\n";
    std::cout << std::string(70, '=') << "\n";
}

void PrintSubHeader(const std::string& subtitle) {
    std::cout << "\n[*] " << subtitle << "\n";
}