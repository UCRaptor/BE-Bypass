#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <stdlib.h>
#include <stdio.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <map>

#if defined(DEBUG)
bool ManualMap(HANDLE hProcess, const std::wstring& dllPath);
#else
bool ManualMap(HANDLE hProcess, PVOID buffer);
#endif

