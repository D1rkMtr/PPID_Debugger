#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

int Error(const char* msg) {
	printf("%s (%u)", msg, GetLastError());
	return -1;
}

int GetParentPID(int pid) {
	int ppid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32))
		return Error("Failed in Process32First");

	while (Process32Next(hSnapshot, &pe32)) {
		if (pe32.th32ProcessID == pid) {
			ppid = pe32.th32ParentProcessID;
			break;
		}
	}
	return ppid;
}

int main() {
	int parentPID = GetParentPID(GetCurrentProcessId());
	//printf("parentPID =  %d\n", parentPID);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32))
		return Error("Failed in Process32First");

	while (Process32Next(hSnapshot, &pe32)) {
		if (pe32.th32ProcessID == parentPID) {
			size_t i;
			char* pMBBuffer = (char*)malloc(100);
			const wchar_t* pWCBuffer = pe32.szExeFile;
			wcstombs_s(&i, pMBBuffer, (size_t)100, pWCBuffer, (size_t)100 - 1);
			if (!strcmp(pMBBuffer, "windbg.exe") || !strcmp(pMBBuffer, "x64dbg.exe") ||
				!strcmp(pMBBuffer, "ImmunityDebugger.exe") || !strcmp(pMBBuffer, "OLLYDBG.exe")) {
				MessageBox(NULL, L"DEBUGGER DETECTED", L"", MB_OK);
				return -1;
			}
		}
		
		//printf("ImageFile %ws   PID %d\n", pe32.szExeFile, pe32.th32ProcessID);
	}
	MessageBox(NULL, L"NO DEBUGGER DETECTED", L"", MB_OK);
	return 1;
}