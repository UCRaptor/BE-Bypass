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

#include <shlobj.h>
#include <process.h>

#include <mscat.h>

#include <WinTrust.h>
#pragma comment(lib, "Wintrust.lib")

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include "ntdll.h"
#pragma comment(lib,"ntdll.lib")

#include <aclapi.h>

#include "MinHook\minhook.h"


decltype(&NtQuerySecurityObject) oNtQuerySecurityObject;

NTSTATUS
NTAPI
hkNtQuerySecurityObject(
	IN HANDLE ObjectHandle,
	IN SECURITY_INFORMATION SecurityInformation,
	OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN ULONG DescriptorLength,
	OUT PULONG ReturnLength
)
{
	FILE* tt = fopen("C:\\tt.txt", "a+");
	fprintf(tt, "hkNtQuerySecurityObject: %x\n", ObjectHandle);
	fflush(tt);
	fclose(tt);

	CloseHandle(ObjectHandle);

	ObjectHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 3828);

	return oNtQuerySecurityObject(ObjectHandle, SecurityInformation, SecurityDescriptor, DescriptorLength, ReturnLength);
}

typedef BOOL(WINAPI* tCryptCATAdminCalcHashFromFileHandle)(
	_In_    HANDLE hFile,
	_Inout_ DWORD  *pcbHash,
	_In_    BYTE   *pbHash,
	_In_    DWORD  dwFlags
	);

tCryptCATAdminCalcHashFromFileHandle calchash;

BYTE* MYDLLHASH = 0;
bool dllInjected = false;

BOOL WINAPI hkCryptCATAdminCalcHashFromFileHandle(
	_In_    HANDLE hFile,
	_Inout_ DWORD  *pcbHash,
	_In_    BYTE   *pbHash,
	_In_    DWORD  dwFlags
)
{
	CHAR name[255];

	GetFinalPathNameByHandleA(hFile, name, 255, 0x0);

	if (strcmp(PathFindFileNameA(name), "cheat.dll") == 0)
	{
		if (pbHash == 0)
		{
			WCHAR szPath[MAX_PATH];
			if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_SYSTEM, NULL, 0, szPath)))
			{
				CloseHandle(hFile);

				WCHAR fullpath[MAX_PATH];
				swprintf(fullpath, L"%s\\%s", szPath, L"kernel32.dll");
				hFile = CreateFileW(fullpath, GENERIC_READ, 7, NULL, OPEN_EXISTING, 0, NULL);

				//fflush(tt);
				//fclose(tt);
			}
		}
		else
			MYDLLHASH = pbHash;
	}

	/*if (strlen(name) > 0)
	{
		FILE* tt = fopen("C:\\tt.txt", "a+");
		fprintf(tt, "%s\n", name);
		fflush(tt);
		fclose(tt);
	}*/

	return calchash(hFile, pcbHash, pbHash, dwFlags);
}

typedef LONG(WINAPI* tWinVerifyTrust)(
	_In_ HWND   hWnd,
	_In_ GUID   *pgActionID,
	_In_ LPVOID pWVTData
	);

tWinVerifyTrust oWinVerifyTrust;

LONG WINAPI hkWinVerifyTrust(
	_In_ HWND   hWnd,
	_In_ GUID   *pgActionID,
	_In_ LPVOID pWVTData
)
{
	oWinVerifyTrust(hWnd, pgActionID, pWVTData);

	return ERROR_SUCCESS;
}

typedef
HCATINFO(WINAPI* tCryptCATAdminEnumCatalogFromHash)(
	_In_ HCATADMIN hCatAdmin,
	_In_ BYTE      *pbHash,
	_In_ DWORD     cbHash,
	_In_ DWORD     dwFlags,
	_In_ HCATINFO  *phPrevCatInfo
	);
	
tCryptCATAdminEnumCatalogFromHash oCryptCATAdminEnumCatalogFromHash;

HCATINFO hkCryptCATAdminEnumCatalogFromHash(
	_In_ HCATADMIN hCatAdmin,
	_In_ BYTE      *pbHash,
	_In_ DWORD     cbHash,
	_In_ DWORD     dwFlags,
	_In_ HCATINFO  *phPrevCatInfo
)
{
	if (MYDLLHASH != 0 && pbHash == MYDLLHASH)
	{
		dllInjected = true;
	}

	HCATINFO ret = oCryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo);

	return ret;
}

typedef
NTSTATUS
(
NTAPI*
tOpenProcess)(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
);

tOpenProcess oOpen;
HANDLE hnd = INVALID_HANDLE_VALUE;

BOOL GrantRights(HANDLE hProcess)
{
	FILE* tt = fopen("C:\\tt2.txt", "a+");
	fprintf(tt, "uno");
	fflush(tt);

	SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, 0, NULL);
	
	fprintf(tt, "får");
	fflush(tt);

	fclose(tt);

	return TRUE;
}

NTSTATUS
NTAPI hkOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
)
{
	FILE* tt = fopen("C:\\tt2.txt", "a+");
	fprintf(tt, "0x%x\n", DesiredAccess);
	fflush(tt);
	fclose(tt);

	oOpen(ProcessHandle, PROCESS_ALL_ACCESS, ObjectAttributes, ClientId);

	GrantRights(*ProcessHandle);

	auto ret = oOpen(&hnd, PROCESS_ALL_ACCESS, ObjectAttributes, ClientId);

	return ret;
}

typedef NTSTATUS(NTAPI* tNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
tNtReadVirtualMemory ReadVirtualMemory;

void Thread(void*)
{
	MH_Initialize();

	MH_CreateHook(CryptCATAdminCalcHashFromFileHandle, hkCryptCATAdminCalcHashFromFileHandle, &reinterpret_cast<PVOID&>(calchash));
	MH_EnableHook(CryptCATAdminCalcHashFromFileHandle);

	MH_CreateHook(WinVerifyTrust, hkWinVerifyTrust, &reinterpret_cast<PVOID&>(oWinVerifyTrust));
	MH_EnableHook(WinVerifyTrust);


	MH_CreateHook(CryptCATAdminEnumCatalogFromHash, hkCryptCATAdminEnumCatalogFromHash, &reinterpret_cast<PVOID&>(oCryptCATAdminEnumCatalogFromHash));
	MH_EnableHook(CryptCATAdminEnumCatalogFromHash);

	while (true)
	{
		Sleep(1);
	}

	MH_DisableHook(CryptCATAdminCalcHashFromFileHandle);
	MH_DisableHook(WinVerifyTrust);
	MH_DisableHook(CryptCATAdminEnumCatalogFromHash);

	MH_Uninitialize();
}

DWORD WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		_beginthread(Thread, 0, 0);
	}

	return TRUE;
}