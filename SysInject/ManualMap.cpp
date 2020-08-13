/**
* Overlord Project
* Copyright (C) 2016-2017 RangeMachine
*/

#include "ManualMap.h"

typedef struct _CLIENT_ID
{
	HANDLE hProcess;
	HANDLE hThread;
} CLIENT_ID, *PCLIENT_ID;

typedef HMODULE(APIENTRY* LPFN_LOADLIBRARY)(LPCSTR);
typedef FARPROC(APIENTRY* LPFN_GETPROCADDRESS)(HMODULE, LPCSTR);
typedef BOOL(WINAPI *LPFN_DLLMAIN)(HMODULE, DWORD, PVOID);
typedef NTSTATUS(NTAPI* LPFN_RTLCREATEUSERTHREAD)(HANDLE, PSECURITY_DESCRIPTOR, BOOL, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PCLIENT_ID);
typedef INT(WINAPI *LPFN_MESSAGEBOX)(HWND, LPCSTR, LPCSTR, UINT);

typedef struct _LOADER_PARAMETERS
{
	PVOID pImageBase;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_BASE_RELOCATION pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	LPFN_LOADLIBRARY fLoadLibrary;
	LPFN_GETPROCADDRESS fGetProcAddress;
	LPFN_MESSAGEBOX fMessageBox;
} LOADER_PARAMETERS, *PLOADER_PARAMETERS;

uint32_t Loader(PVOID loaderParameters)
{
	// Get loader parameters from address
	PLOADER_PARAMETERS pParameters = reinterpret_cast<PLOADER_PARAMETERS>(loaderParameters);

	PIMAGE_BASE_RELOCATION pBaseRelocation = pParameters->pBaseRelocation;

	DWORD64 delta = reinterpret_cast<uint64_t>((reinterpret_cast<LPBYTE>(pParameters->pImageBase) - pParameters->pNtHeaders->OptionalHeader.ImageBase));

	// Relocate the image
	while (pBaseRelocation->VirtualAddress)
	{
		if (pBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			uint64_t count = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint64_t);
			uint64_t* list = reinterpret_cast<uint64_t*>(pBaseRelocation + 1);


			for (uint64_t i = 0; i < count; i++)
			{
				if (list[i])
				{
					uint64_t *pointer = reinterpret_cast<uint64_t*>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + (pBaseRelocation->VirtualAddress + (list[i] & 0xFFF)));

					*pointer += delta;
				}
			}
		}

		pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<LPBYTE>(pBaseRelocation) + pBaseRelocation->SizeOfBlock);
	}

	// Resolve DLL imports
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = pParameters->pImportDescriptor;

	while (pImportDescriptor->Characteristics)
	{
		PIMAGE_THUNK_DATA originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + pImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + pImportDescriptor->FirstThunk);

		HMODULE hModule = pParameters->fLoadLibrary(reinterpret_cast<LPCSTR>(pParameters->pImageBase) + pImportDescriptor->Name);

		if (!hModule)
		{
			pParameters->fMessageBox(0, reinterpret_cast<LPCSTR>(pParameters->pImageBase) + pImportDescriptor->Name, 0, MB_OK | MB_ICONERROR);

			return 0;
		}

		while (originalThunk->u1.AddressOfData)
		{
			if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				uint64_t function = reinterpret_cast<uint64_t>(pParameters->fGetProcAddress(hModule, reinterpret_cast<LPCSTR>(originalThunk->u1.Ordinal & 0xFFFF)));

				if (!function)
					return 0;

				firstThunk->u1.Function = function;
			}

			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + originalThunk->u1.AddressOfData);

				uint64_t function = reinterpret_cast<uint64_t>(pParameters->fGetProcAddress(hModule, reinterpret_cast<LPCSTR>(importByName->Name)));


				if (!function)
					return 0;

				firstThunk->u1.Function = function;
			}

			originalThunk++;
			firstThunk++;
		}

		pImportDescriptor++;
	}

	if (pParameters->pNtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		LPFN_DLLMAIN fEntryPoint = reinterpret_cast<LPFN_DLLMAIN>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + pParameters->pNtHeaders->OptionalHeader.AddressOfEntryPoint);

		// Call the entry point
		return fEntryPoint(reinterpret_cast<HMODULE>(pParameters->pImageBase), DLL_PROCESS_ATTACH, NULL);
	}

	return 0;
}

uint32_t LoaderEnd()
{
	return 0;
}

#if defined(DEBUG)
bool ManualMap(HANDLE hProcess, const std::wstring& dllPath)
#else
bool ManualMap(HANDLE hProcess, PVOID pBuffer)
#endif
{
#if defined(DEBUG)
	HANDLE hFile = CreateFile(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (!hFile)
		{printf("ERROR: %d", GetLastError()); return false;}

	DWORD fileSize = GetFileSize(hFile, NULL);
	PVOID pBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	DWORD bytesRead;

	if (!ReadFile(hFile, pBuffer, fileSize, &bytesRead, NULL))
	{
		CloseHandle(hFile);

		{printf("ERROR: %d", GetLastError()); return false;}
	}

	CloseHandle(hFile);
#endif

	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBuffer);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{printf("IMAGE_DOS_SIGNATURE: %d", GetLastError()); return false;}

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<LPBYTE>(pBuffer) + pDosHeader->e_lfanew));

	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{printf("IMAGE_NT_SIGNATURE: %d", GetLastError()); return false;}

	if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL))
		{printf("IMAGE_FILE_DLL: %d", GetLastError()); return false;}

	// Allocate memory for the DLL
	PVOID pImageBase = VirtualAllocEx(hProcess, 0, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pImageBase)
		{printf("pImageBase: %d", GetLastError()); return false;}

	// Copy the header to target process
	if (!WriteProcessMemory(hProcess, pImageBase, pBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL))
		{printf("WriteProcessMemory: %d", GetLastError()); return false;}

	PIMAGE_SECTION_HEADER pSectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(pNtHeaders + 1);


	for (uint64_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)

	{
		if (!WriteProcessMemory(
			hProcess,
			reinterpret_cast<PVOID>(reinterpret_cast<LPBYTE>(pImageBase) + pSectionHeaders[i].VirtualAddress),
			reinterpret_cast<PVOID>(reinterpret_cast<LPBYTE>(pBuffer) + pSectionHeaders[i].PointerToRawData),
			pSectionHeaders[i].SizeOfRawData,
			NULL))
		{
			{printf("WriteProcessMemory: %d", GetLastError()); return false;}
		}
	}

	// Copy the loader to target process

	uint64_t loaderSize = reinterpret_cast<PBYTE>(LoaderEnd) - reinterpret_cast<PBYTE>(Loader);


	PVOID pLoader = VirtualAllocEx(hProcess, NULL, loaderSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!pLoader)
		{printf("pLoader: %d", GetLastError()); return false;}

	if (!WriteProcessMemory(hProcess, pLoader, reinterpret_cast<PVOID>(Loader), loaderSize, NULL))
		{printf("WriteProcessMemory: %d", GetLastError()); return false;}

	// Copy parameters to target process
	LOADER_PARAMETERS parameters;

	parameters.pImageBase = pImageBase;
	parameters.pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<LPBYTE>(pImageBase) + pDosHeader->e_lfanew);
	parameters.pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<LPBYTE>(pImageBase) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	parameters.pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<LPBYTE>(pImageBase) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	parameters.fLoadLibrary = reinterpret_cast<LPFN_LOADLIBRARY>(GetProcAddress(GetModuleHandleA(("kernel32.dll")), ("LoadLibraryA")));
	parameters.fGetProcAddress = reinterpret_cast<LPFN_GETPROCADDRESS>(GetProcAddress(GetModuleHandleA(("kernel32.dll")), ("GetProcAddress")));
	parameters.fMessageBox = reinterpret_cast<LPFN_MESSAGEBOX>(GetProcAddress(GetModuleHandleA(("user32.dll")), ("MessageBoxA")));

	PVOID pParameters = VirtualAllocEx(hProcess, NULL, sizeof(parameters), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!pParameters)
		{printf("pParameters: %d", GetLastError()); return false;}

	if (!WriteProcessMemory(hProcess, pParameters, &parameters, sizeof(parameters), NULL))
		{printf("WriteProcessMemory: %d", GetLastError()); return false;}

	HANDLE hThread;
	CLIENT_ID clientId;

	LPFN_RTLCREATEUSERTHREAD fRtlCreateUserThread = reinterpret_cast<LPFN_RTLCREATEUSERTHREAD>(GetProcAddress(GetModuleHandle("ntdll.dll"), ("RtlCreateUserThread")));
	fRtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, pLoader, pParameters, &hThread, &clientId);


	printf("INJECTED!\n");

	// Clean memory
	VirtualFreeEx(hProcess, pLoader, loaderSize, MEM_FREE);
	VirtualFreeEx(hProcess, pParameters, sizeof(parameters), MEM_FREE);
	VirtualFreeEx(hProcess, pImageBase, 0x1000, MEM_FREE);

	return true;
}