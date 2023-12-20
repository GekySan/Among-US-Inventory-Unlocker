using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace AUS_IUnlocker
{
    internal class MemoryUtilities
    {
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static (byte[] pattern, byte[] mask) ConvertSignatureToPatternAndMask(string signature)
        {
            var signatureParts = signature.Split(' ');
            var pattern = new byte[signatureParts.Length];
            var mask = new byte[signatureParts.Length];

            for (int i = 0; i < signatureParts.Length; i++)
            {
                if (signatureParts[i] == "??")
                {
                    pattern[i] = 0x00;
                    mask[i] = 0x00;
                }
                else
                {
                    pattern[i] = Convert.ToByte(signatureParts[i], 16);
                    mask[i] = 0xFF;
                }
            }

            return (pattern, mask);
        }

        public static IntPtr SignatureScan(Process process, IntPtr baseAddress, int scanSize, byte[] pattern, byte[] mask)
        {
            byte[] buffer = new byte[scanSize];
            int bytesRead = 0;
            ReadProcessMemory(process.Handle, baseAddress, buffer, scanSize, ref bytesRead);

            for (int i = 0; i < scanSize - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (mask[j] != 0x00 && pattern[j] != buffer[i + j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return new IntPtr(baseAddress.ToInt64() + i);
                }
            }

            return IntPtr.Zero;
        }

        public static bool PatchBytes(Process process, IntPtr address, byte[] patch)
        {
            if (!VirtualProtectEx(process.Handle, address, (uint)patch.Length, 0x40, out uint oldProtect)) // 0x40 = PAGE_EXECUTE_READWRITE - https://learn.microsoft.com/fr-fr/windows/win32/memory/memory-protection-constants
            {
                return false;
            }

            bool result = WriteProcessMemory(process.Handle, address, patch, (uint)patch.Length, out int bytesWritten);

            VirtualProtectEx(process.Handle, address, (uint)patch.Length, oldProtect, out _);

            return result && bytesWritten == patch.Length;
        }
    }
}
