using System;
using System.Runtime.InteropServices;

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

namespace SysCallLib
{
    public class ManualSyscall
    {
        private IntPtr funcAddress { get; set; }
        private bool isWow64 { get; set; }
        public IntPtr allocatedShellCode { get; set; }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate NtStatus NtAllocateVirtualMemory
            (
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref uint RegionSize,
                MemoryAllocationType AllocationType,
                PageAccessType Protect
            );

        public ManualSyscall(string moduleName, string funcName, bool isWow64)
        {
            this.funcAddress = Resolver.GetExportAddress(moduleName, funcName);
            this.isWow64 = isWow64;
            this.allocatedShellCode = IntPtr.Zero;
        }

        public IntPtr AllocateShellCode()
        {
            byte[] shellcode;
            int syscallId;

            if (isWow64)
            {
                shellcode = new byte[]
                {
                                                    //https://defuse.ca/online-x86-assembler.htm#disassembly
                    0xB8, 0x00, 0x00, 0x00, 0x00,   //mov     eax, syscallId
                    0xBA, 0x00, 0x00, 0x00, 0x00,   //mov     edx, offset _Wow64SystemServiceCall@0 ; Wow64SystemServiceCall()
                    0xFF, 0xD2,                     //call    edx ; Wow64SystemServiceCall() ; Wow64SystemServiceCall()
                    0xC3                            //retn    2Ch 
                };

                IntPtr wow64Address = Resolver.GetExportAddress("ntdll.dll", "Wow64Transition");

                syscallId = Marshal.ReadInt32(funcAddress + 1, 0);//offset of + 1 comes from asm above

                byte[] syscallIdBytes = BitConverter.GetBytes(syscallId);

                Buffer.BlockCopy(syscallIdBytes, 0, shellcode, 1, sizeof(uint));

                int wow64Transition = Marshal.ReadInt32(wow64Address, 0);

                var wow64TransitionBytes = BitConverter.GetBytes(wow64Transition);

                Buffer.BlockCopy(wow64TransitionBytes, 0, shellcode, 6, sizeof(uint));
            }
            else
            {
                shellcode = new byte[]
                {
                                                    // //https://defuse.ca/online-x86-assembler.htm#disassembly
                    0x4C, 0x8B, 0xD1,               // mov r10,rcx
                    0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, 0x00 (syscall identifier)
                    0x0F, 0x05,                     // syscall
                    0xC3                            // retn
                };

                syscallId = Marshal.ReadInt32(funcAddress + 4, 0);//offset of + 4 comes from asm above

                var syscallIdentifierBytes = BitConverter.GetBytes(syscallId);

                Buffer.BlockCopy(syscallIdentifierBytes, 0, shellcode, 4, sizeof(uint));
            }

            IntPtr ntVirtualAlloc = Resolver.GetExportAddress("ntdll.dll", "NtAllocateVirtualMemory");

            NtAllocateVirtualMemory ntAllocateVirtualMemory = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntVirtualAlloc, typeof(NtAllocateVirtualMemory));

            IntPtr alloc = IntPtr.Zero;
            uint sizeOfShellCode = (uint)shellcode.Length;

            ntAllocateVirtualMemory((IntPtr)(-1), ref alloc, IntPtr.Zero, ref sizeOfShellCode, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, PageAccessType.PAGE_EXECUTE_READWRITE);

            Marshal.Copy(shellcode, 0, alloc, shellcode.Length);

            allocatedShellCode = alloc;

            return alloc;
            //return shellcode;
        }

        public void Dispose() 
        {
            Marshal.FreeHGlobal(allocatedShellCode);
        }
    }
}
