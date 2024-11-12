# WinAPI

This section shows shellcode injection using the APIs of `kernel32.dll`.

This example is just a starting point to compare the different techniques and understand how they differ. We won’t get into the nitty-gritty details of the injection itself — there are plenty of guides out there that cover that in depth.

The shellcode used triggers a basic popup window. We’re not diving into msfvenom or anything related to evading signature-based detection since the main focus here is to see how system calls are executed. However, we've included some encryption/decryption logic to make it feel a bit more like what you'd see in a real-world scenario.

**The goal of this example is also to make sure that this scenario actually triggers the AV. Once we confirm that, in the following sections, we’ll see if simply changing how system calls are executed allows us to perform the same actions without getting blocked.**

## Test Result
Tests confirm that as soon as it's run, the PE gets blocked right away and flagged as malicious.

<p align="center">
  <img width="460" src="https://github.com/user-attachments/assets/80e4dc15-f744-454f-80ea-18969a287d3a">
</p>

## References

[https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)\
[https://www.ired.team/offensive-security/code-injection-process-injection/process-injection](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection)\
... and many more

