# SysCalling

## What is this?

SysCalling is an **educational project** designed to showcase *state-of-the-art* syscall execution techniques for bypassing **user-space** EDR controls in a Windows x64 environment.
Currently, the project covers the following areas:
- [x] [Windows Kernel32 API](<1. WinAPI/README.md>)
- [x] [Direct Syscall](<2. DirectSyscall/README.md>)
- [x] [Indirect Syscall](<3. IndirectSyscall/README.md>)
- [x] [Vectored Syscall](<4. VectoredSyscall/README.md>)

## Why on the earth?

It's just something I'm really passionate about and have been working on for the past few months, and I didn't want to keep it to myself.

While there are plenty of blogs and articles on the topic, this could also serve as a valuable space to bring together all the knowledge on the subject.

## How?

SysCalling uses a classic shellcode injection scenario to illustrate the differences between techniques in a straightforward yet comprehensive attack simulation. This is a well-known attack pattern, so any EDR should be able to recognize and block it. This allows us to assess how the syscall techniques demonstrated here can help malicious software conceal its true intentions.

My personal test results are summarized below. The table shows whether or not the 'attack' was successful on a system protected by New-Gen AV, which uses inline hooking for detection.

|  WIN API | DIRECT SYSCALL | INDIRECT SYSCALL | VECTORED SYSCALL |
|----------|----------------|------------------|------------------|
| :x: | :x: | :white_check_mark: | :white_check_mark: |

## Who
[@UmaRex01](https://x.com/umarex01)
