#include "ManualMap.h"
#include "Sys.h"

using namespace std;

#define DEBUGGER_CHECK() \
	if (IsDebuggerPresent()) \
		TerminateProcess(reinterpret_cast<HANDLE>(-1), 0xDEAD);

bool RaisePrivileges()
{
	DEBUGGER_CHECK();

	HANDLE hToken;
	TOKEN_PRIVILEGES privileges;

	if (OpenProcessToken(reinterpret_cast<HANDLE>(-1), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		privileges.Privileges[0].Luid.LowPart = 20;
		privileges.Privileges[0].Luid.HighPart = 0;

		AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL);
		CloseHandle(hToken);

		return true;
	}

	return false;
}

// Get the size of a file
long getFileSize(FILE *file)
{
	long lCurPos, lEndPos;
	lCurPos = ftell(file);
	fseek(file, 0, 2);
	lEndPos = ftell(file);
	fseek(file, lCurPos, 0);
	return lEndPos;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

DWORD GetPID(char *processName) {
	DWORD pid = 0;
	HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 procStruct;
	procStruct.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(Snap, &procStruct)) {
		do {
			if (!strcmp(processName, procStruct.szExeFile)) {
				pid = (UINT32)procStruct.th32ProcessID;
				break;
			}
		} while (Process32Next(Snap, &procStruct));
	}
	CloseHandle(Snap);
	return(pid);
}

DWORD GetThreadID(DWORD pid) {
	HANDLE hsnap;
	THREADENTRY32 pt;
	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	pt.dwSize = sizeof(THREADENTRY32);
	while (Thread32Next(hsnap, &pt)) {
		if (pt.th32OwnerProcessID == pid) {
			DWORD Thpid = pt.th32ThreadID;
			CloseHandle(hsnap);
			return Thpid;
		}
	};
	CloseHandle(hsnap);
	return 0;
}

HHOOK handle;
HMODULE dll;
bool SetHook()
{
	DWORD pid = 0;
	while (pid == 0)
	{
		pid = GetPID("Game.exe");
	}

	printf("Game found!\n");

	dll = LoadLibraryA("cheat.dll");

	/*
	* Get the address of the function inside the DLL.
	*/
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "derp");
	if (addr == NULL) {
		printf("error 1\n");
		Sleep(500);
		return false;
	}

	while (FindWindow("Game", 0) == NULL)
	{
		Sleep(5);
	}

	printf("GETTING TID!\n");

	DWORD tid = 0;
	while ((tid = GetThreadID(pid)) == 0)
	{
		Sleep(50);
	}

	printf("SETTING HOOK!\n");

	/*
	* Hook the function.
	*/
	handle = SetWindowsHookExA(WH_GETMESSAGE, addr, dll, tid);
	if (handle == NULL) {
		printf("error 2 (%d)\n", GetLastError());
		Sleep(1500);
		return false;
	}




	while (true)
	{
		if (GetAsyncKeyState(VK_INSERT) & 1)
			break;

		Sleep(250);
	}

	UnhookWindowsHookEx(handle);

	return true;
}

int main()
{
	if (!IsElevated())
	{
		printf("Run as admin...\n");
		Sleep(500);
		ExitProcess(EXIT_FAILURE);
	}


	//const char *filePath = "Sys.dll";
//	BYTE *fileBuf;
//	FILE *file = NULL;

	//if ((file = fopen(filePath, "rb")) == NULL)
	//	cout << "Could not open specified file" << endl;
	///else
	//	cout << "File opened successfully\n" << endl;

	// Get the size of the file in bytes
	//long fileSize = getFileSize(file);

	// Allocate space in the buffer for the whole file
	//fileBuf = new BYTE[fileSize];

	// Read the file in to the buffer
	//fread(fileBuf, fileSize, 1, file);

	/*FILE *log;
	fopen_s(&log, "C:\\sysss.txt", "a+");
	int c = 0;
	for (int i = 0; i < fileSize; ++i)
	{
		++c;
		if (c > 10)
		{
			fprintf(log, "\n");
			fflush(log);
			c = 0;
		}

		fprintf(log, "0x%x, ", fileBuf[i]);
	}
	fclose(log);*/
	

	RaisePrivileges();

	HANDLE hService = 0;

	while(!hService)
	{
		hService = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetPID("BEService.exe"));
		Sleep(500);
	}

	while (!ManualMap(hService, (PVOID)sysdll))
	{
		wprintf(L"Could not apply memory patch.\n");
		Sleep(500);
	}

	CloseHandle(hService);
	
	bool ret = SetHook();

	return 0;
}