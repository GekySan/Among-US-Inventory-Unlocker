using System;
using System.Diagnostics;

namespace AUS_IUnlocker
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Process gameProcess = ProcessUtilities.AttachProcess("Among Us");
            if (gameProcess == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Game not found or cannot be attached.");
                Console.ResetColor();

                Console.WriteLine("Press Enter to continue...");
                Console.ReadLine();
                return;
            }

            // Console.WriteLine($"Attached to process {gameProcess.ProcessName} with ID {gameProcess.Id}.");

            if (!TryPatchAmongUS(gameProcess))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Failed to patch the game.");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Patch successfully applied.");
                Console.ResetColor();
            }

            Console.WriteLine("Press Enter to continue...");
            Console.ReadLine();
        }

        private static bool TryPatchAmongUS(Process gameProcess)
        {
            const string moduleName = "GameAssembly.dll";
            var (baseAddress, moduleSize) = ProcessUtilities.GetModuleInfo(moduleName, gameProcess.Id);
            if (baseAddress == IntPtr.Zero)
            {
                Console.WriteLine("GameAssembly.dll module not found.");
                return false;
            }

            // Console.WriteLine($"Base address of GameAssembly.dll: {baseAddress:X}, Size: {moduleSize}");

            string signature = "74 05 B0 01 5E 5D C3 A1 ?? ?? ?? ?? F6";
            var (pattern, mask) = MemoryUtilities.ConvertSignatureToPatternAndMask(signature);

            IntPtr address = MemoryUtilities.SignatureScan(gameProcess, baseAddress, moduleSize, pattern, mask);
            if (address == IntPtr.Zero)
            {
                Console.WriteLine("Signature not found.");
                return false;
            }

            // Console.WriteLine($"Signature found at address: {address:X}");

            byte[] patch = { 0x90, 0x90 }; // NOP, NOP in x86: https://en.wikipedia.org/wiki/NOP_(code)
            if (MemoryUtilities.PatchBytes(gameProcess, address, patch))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}