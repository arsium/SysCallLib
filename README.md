# A manual syscall lib 

A small libary to execute shellcode manually from .net application. Useful for red teams.<br>
This small libary allows you to make syscalls based on following patterns :

x64 :

```assembly
mov r10,rcx
mov eax, 0x00 ;(syscall identifier)
syscall
retn
```

x86 :


```assembly
;dump from IDA
mov     eax, syscallId
mov     edx, offset _Wow64SystemServiceCall@0 ; Wow64SystemServiceCall()
call    edx ; Wow64SystemServiceCall() ; Wow64SystemServiceCall()
retn    
```

Some explainations are required for x86. Windows X86 or WoW64 changes pattern of syscall in nearly all version of Windows.

This "Wow64SystemServiceCall" calls an exported DWORD called "WoW64Transition" that contains an address to switch to X64 syscall mode.

![PIC1](https://github.com/arsium/SysCallLib/blob/main/Pictures/1_32.png?raw=true)
<br>
![PIC1](https://github.com/arsium/SysCallLib/blob/main/Pictures/1_32_2.png?raw=true)
<br>
![PIC1](https://github.com/arsium/SysCallLib/blob/main/Pictures/3_32.png?raw=true)
<br>
![PIC1](https://github.com/arsium/SysCallLib/blob/main/Pictures/6_32.png?raw=true)

Same as :


```assembly
;syscall from Windows 8.1 (working for compatibility with 10 & 11)
mov eax, syscall identifier;
call *large* dword ptr fs : 0C0h
retn   
```

This address in "WoW64Transition" is dynamic so it needs to be resolved every time.



Sample of uses :

```csharp
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint NtAllocateVirtualMemory
(
   IntPtr ProcessHandle,
   ref IntPtr BaseAddress,
   IntPtr ZeroBits,
   ref uint RegionSize,
   MemoryAllocationType AllocationType,
   PageAccessType Protect
);
SysCallLib.ManualSyscall ntAlloc = new SysCallLib.ManualSyscall("ntdll.dll", "NtAllocateVirtualMemory", true);
ntAlloc.AllocateShellCode();
NtAllocateVirtualMemory ntAllocDel = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntAlloc.allocatedShellCode, typeof(NtAllocateVirtualMemory));
```

Ref :
* [malwaretech](https://www.malwaretech.com/2015/07/windows-10-system-call-stub-changes.html)
* [unknowncheats](https://www.unknowncheats.me/forum/assembly/148398-manual-syscalls-using-assembly-x64.html)
* [gist syscall stub](https://gist.github.com/wbenny/b08ef73b35782a1f57069dff2327ee4d)
