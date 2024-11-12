#include "Utils.h"
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>

DWORD FindProcessByName(const TCHAR* procName)
{
	HANDLE hSnapshot;
	DWORD dwProcId = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_tcsicmp(pe32.szExeFile, procName) == 0) {
				dwProcId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return dwProcId;
}