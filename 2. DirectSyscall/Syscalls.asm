EXTERN avmSSN: DWORD
EXTERN wvmSSN: DWORD
EXTERN pvmSSN: DWORD
EXTERN cteSSN: DWORD

_TEXT SEGMENT
PUBLIC NtAllocateVirtualMemory
PUBLIC NtWriteVirtualMemory
PUBLIC NtProtectVirtualMemory
PUBLIC NtCreateThreadEx

NtAllocateVirtualMemory PROC
	mov r10, rcx
	mov eax, avmSSN
	syscall
	ret
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov r10, rcx
	mov eax, wvmSSN
	syscall
	ret
NtWriteVirtualMemory ENDP

NtProtectVirtualMemory PROC
	mov r10, rcx
	mov eax, pvmSSN
	syscall
	ret
NtProtectVirtualMemory ENDP

NtCreateThreadEx PROC
	mov r10, rcx
	mov eax, cteSSN
	syscall
	ret
NtCreateThreadEx ENDP

_TEXT ENDS
END