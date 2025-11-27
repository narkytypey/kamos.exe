//WORD
#pragma once


#include <string>
#include <windows.h> 

void EnumTokenInfo();
void EnumNetworkAdapters();
void EnumProcesses();
void GetSystemInformation();
void ListDirectory(const std::string& dirPath);
std::string GetIntegrityLevel(DWORD dwIntegrity);