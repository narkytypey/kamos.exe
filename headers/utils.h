//WORD
#pragma once

#ifndef WINVER
#define WINVER 0x0A00  // Windows 10
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <ifmib.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <sddl.h>
#include <lm.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

// linking important libs
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "shell32.lib")

// function notifications
std::wstring GetErrorMessage(DWORD error);
std::string WideToString(const wchar_t* wide);
std::wstring StringToWide(const std::string& str);
void PrintHeader(const std::string& title);
void PrintSubHeader(const std::string& subtitle);