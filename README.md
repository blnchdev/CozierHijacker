# Cozier Hijacker
Another bit of a meme that hijacks a handle to a given process, using [ComfierSyscalls](https://github.com/blnchdev/ComfierSyscalls) which is my dynamic direct syscall wrapper; there is virtually no need to ever use direct syscalls in your own process to hijack handles, just thought it was funny to do.  
Also, this uses std::optional, just because I like C++20  
  
This is for educational uses only, and in any ways this would virtually not cause any harm ever- hijacking a handle is either not possible or "detected" by EDRs and Kernel Mode Anti-Cheats

### Credits
[NtDoc](https://ntdoc.m417z.com/) for NtAPI Definitions
