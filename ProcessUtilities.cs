using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace AUS_IUnlocker
{
    internal class ProcessUtilities
    {

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);
        public static bool IsRunning(int procId)
        {
            try
            {
                Process.GetProcessById(procId);
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        public static string ProcessIdToName(int procId)
        {
            try
            {
                Process proc = Process.GetProcessById(procId);
                return proc.ProcessName;
            }
            catch (ArgumentException)
            {
                return "Processus introuvable";
            }
        }

        public static (IntPtr BaseAddress, int ModuleSize) GetModuleInfo(string moduleName, int procId)
        {
            Process proc = Process.GetProcessById(procId);
            ProcessModule module = proc.Modules.Cast<ProcessModule>().FirstOrDefault(m => string.Equals(m.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase));

            if (module != null)
            {
                return (module.BaseAddress, module.ModuleMemorySize);
            }

            return (IntPtr.Zero, 0);
        }

        public static Process AttachProcess(string windowTitle)
        {
            IntPtr hWnd = FindWindow(null, windowTitle);

            if (hWnd != IntPtr.Zero)
            {
                GetWindowThreadProcessId(hWnd, out int processId);
                try
                {
                    return Process.GetProcessById(processId);
                }
                catch (ArgumentException)
                {
                    Console.WriteLine($"Aucun processus avec l'ID {processId} n'a été trouvé.");
                }
            }
            return null;
        }

    }
}
