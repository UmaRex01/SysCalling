EXTERN avmSSN: DWORD
EXTERN wvmSSN: DWORD
EXTERN pvmSSN: DWORD
EXTERN cteSSN: DWORD

EXTERN avmADDR: QWORD
EXTERN wvmADDR: QWORD
EXTERN pvmADDR: QWORD
EXTERN cteADDR: QWORD

_TEXT SEGMENT
PUBLIC NtAllocateVirtualMemory
PUBLIC NtWriteVirtualMemory
PUBLIC NtProtectVirtualMemory
PUBLIC NtCreateThreadEx

NtAllocateVirtualMemory PROC
	mov r10, rcx
	mov eax, avmSSN
	jmp QWORD PTR [avmADDR]
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov r10, rcx
	mov eax, wvmSSN
	jmp QWORD PTR [wvmADDR]
NtWriteVirtualMemory ENDP

NtProtectVirtualMemory PROC
	mov r10, rcx
	mov eax, pvmSSN
	jmp QWORD PTR [pvmADDR]
NtProtectVirtualMemory ENDP

NtCreateThreadEx PROC
	mov r10, rcx
	mov eax, cteSSN
	jmp QWORD PTR [cteADDR]
NtCreateThreadEx ENDP

_TEXT ENDS
END