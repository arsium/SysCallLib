using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

namespace Test
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        [Flags]
        internal enum PageAccessType : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
            PAGE_GRAPHICS_NOACCESS = 0x0800,
            PAGE_GRAPHICS_READONLY = 0x1000,
            PAGE_GRAPHICS_READWRITE = 0x2000,
            PAGE_GRAPHICS_EXECUTE = 0x4000,
            PAGE_GRAPHICS_EXECUTE_READ = 0x8000,
            PAGE_GRAPHICS_EXECUTE_READWRITE = 0x10000,
            PAGE_GRAPHICS_COHERENT = 0x20000,
            PAGE_GRAPHICS_NOCACHE = 0x40000,
            PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
            PAGE_REVERT_TO_FILE_MAP = 0x80000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
            PAGE_ENCLAVE_MASK = 0x10000000,
            PAGE_ENCLAVE_DECOMMIT = (PAGE_ENCLAVE_MASK | 0),
            PAGE_ENCLAVE_SS_FIRST = (PAGE_ENCLAVE_MASK | 1),
            PAGE_ENCLAVE_SS_REST = (PAGE_ENCLAVE_MASK | 2)
        }

        [Flags]
        internal enum MemoryAllocationType : uint
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_REPLACE_PLACEHOLDER = 0x00004000,
            MEM_RESERVE_PLACEHOLDER = 0x00040000,
            MEM_RESET = 0x00080000,
            MEM_TOP_DOWN = 0x00100000,
            MEM_WRITE_WATCH = 0x00200000,
            MEM_PHYSICAL = 0x00400000,
            MEM_ROTATE = 0x00800000,
            MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000,
            MEM_RESET_UNDO = 0x01000000,
            MEM_LARGE_PAGES = 0x20000000,
            MEM_4MB_PAGES = 0x80000000,
            MEM_64K_PAGES = (MEM_LARGE_PAGES | MEM_PHYSICAL),
            MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001,
            MEM_COALESCE_PLACEHOLDERS = 0x00000001,
            MEM_PRESERVE_PLACEHOLDER = 0x00000002,
            MEM_DECOMMIT = 0x00004000,
            MEM_RELEASE = 0x00008000,
            MEM_FREE = 0x00010000
        }

        internal enum NtStatus : uint
        {
            Success = 0,
            Informational = 0x40000000,
            Error = 0xc0000000
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NtStatus NtWriteVirtualMemory
            (
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                byte[] Buffer,
                uint NumberOfBytesToWrite,
                out uint NumberOfBytesWritten
            );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NtStatus NtAllocateVirtualMemory
            (
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref uint RegionSize,
                MemoryAllocationType AllocationType,
                PageAccessType Protect
            );

        private void button1_Click(object sender, EventArgs e)
        {
            if (IntPtr.Size == 4)
            {
                SysCallLib.ManualSyscall ntWrite = new SysCallLib.ManualSyscall("ntdll.dll", "NtWriteVirtualMemory", true);
                ntWrite.AllocateShellCode();
                MessageBox.Show("Address of manual syscall shellcode : " + ntWrite.allocatedShellCode.ToString("x"));
                NtWriteVirtualMemory ntWriteVirtualDel = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntWrite.allocatedShellCode, typeof(NtWriteVirtualMemory));

                SysCallLib.ManualSyscall ntAlloc = new SysCallLib.ManualSyscall("ntdll.dll", "NtAllocateVirtualMemory", true);
                ntAlloc.AllocateShellCode();
                NtAllocateVirtualMemory ntAllocDel = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntAlloc.allocatedShellCode, typeof(NtAllocateVirtualMemory));


                byte[] randomBytes = new byte[] { 0x1f, 0x6a, 0x5c, 0x69, 0xef, 0xa9 };
                IntPtr alloc = IntPtr.Zero;
                uint sizeOfrandomBytes = (uint)randomBytes.Length;

                ntAllocDel((IntPtr)(-1), ref alloc, IntPtr.Zero, ref sizeOfrandomBytes, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, PageAccessType.PAGE_EXECUTE_READWRITE);
                MessageBox.Show("Address for random bytes : " + alloc.ToString("x"));
                ntWriteVirtualDel((IntPtr)(-1), alloc, randomBytes, sizeOfrandomBytes, out _);

            }
            else 
            {
                SysCallLib.ManualSyscall ntWrite = new SysCallLib.ManualSyscall("ntdll.dll", "NtWriteVirtualMemory", false);
                ntWrite.AllocateShellCode();
                MessageBox.Show("Address of manual syscall shellcode : " + ntWrite.allocatedShellCode.ToString("x"));
                NtWriteVirtualMemory ntWriteVirtualDel = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntWrite.allocatedShellCode, typeof(NtWriteVirtualMemory));

                SysCallLib.ManualSyscall ntAlloc = new SysCallLib.ManualSyscall("ntdll.dll", "NtAllocateVirtualMemory", false);
                ntAlloc.AllocateShellCode();
                NtAllocateVirtualMemory ntAllocDel = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntAlloc.allocatedShellCode, typeof(NtAllocateVirtualMemory));


                byte[] randomBytes = new byte[] { 0x1f, 0x6a, 0x5c, 0x69, 0xef, 0xa9 };
                IntPtr alloc = IntPtr.Zero;
                uint sizeOfrandomBytes = (uint)randomBytes.Length;

                ntAllocDel((IntPtr)(-1), ref alloc, IntPtr.Zero, ref sizeOfrandomBytes, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, PageAccessType.PAGE_EXECUTE_READWRITE);
                MessageBox.Show("Address for random bytes : " + alloc.ToString("x"));
                ntWriteVirtualDel((IntPtr)(-1), alloc, randomBytes, sizeOfrandomBytes, out _);
            }
        }
    }
}
