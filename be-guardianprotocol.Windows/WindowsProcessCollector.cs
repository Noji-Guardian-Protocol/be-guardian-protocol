using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Services;
using System.Runtime.InteropServices;
using System.Text;

namespace be_guardianprotocol.Windows
{
    public class WindowsProcessCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private static string _currentApp = "";
        private static string _previousApp = "";
        private static DateTime _appSwitchTime = DateTime.Now;
        private static int _appSwitchCount = 0;
        private static readonly Dictionary<string, DateTime> _appStartTimes = new();
        private static readonly Dictionary<string, double> _appCpuUsage = new();
        private static readonly Dictionary<string, long> _appMemoryUsage = new();

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        [DllImport("user32.dll")]
        private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

        public WindowsProcessCollector()
        {
            _logger = new NetworkConnectionLogger();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var activeWindow = GetActiveWindowInfo();
                var processes = Process.GetProcesses();
                var activeProcesses = GetSafeProcessList(processes);

                var capture = new SignalCapture
                {
                    Type = SignalTypes.Process,
                    IsConnected = true,
                    Timestamp = DateTime.Now,
                    
                    // Application info
                    ActiveWindow = activeWindow.WindowTitle,
                    ProcessName = activeWindow.ProcessName,
                    ProcessId = activeWindow.ProcessId,
                    
                    // App switching
                    CurrentApp = activeWindow.ProcessName,
                    PreviousApp = _previousApp,
                    AppSwitchCount = _appSwitchCount,
                    AppForegroundTime = GetAppForegroundTime(activeWindow.ProcessName),
                    
                    // Process counts
                    ActiveProcessCount = activeProcesses.Count,
                    TotalProcessCount = processes.Length,
                    
                    // System performance
                    SystemCpuUsage = GetSystemCpuUsage(),
                    SystemMemoryUsage = GetSystemMemoryUsage(),
                    
                    // Current app performance
                    CurrentAppCpuUsage = GetProcessCpuUsage(activeWindow.ProcessId),
                    CurrentAppMemoryUsage = GetProcessMemoryUsage(activeWindow.ProcessId),
                    CurrentAppProcessCount = GetProcessCountByName(activeWindow.ProcessName)
                };

                // Track app switching
                if (_currentApp != activeWindow.ProcessName)
                {
                    _previousApp = _currentApp;
                    _currentApp = activeWindow.ProcessName;
                    _appSwitchTime = DateTime.Now;
                    _appSwitchCount++;
                    
                    if (!_appStartTimes.ContainsKey(_currentApp))
                        _appStartTimes[_currentApp] = DateTime.Now;
                }

                await _logger.LogConnectionAsync(capture);
                results.Add(capture);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Process collection error: {ex.Message}");
            }

            return results;
        }

        private (string WindowTitle, string ProcessName, int ProcessId) GetActiveWindowInfo()
        {
            try
            {
                IntPtr hwnd = GetForegroundWindow();
                GetWindowThreadProcessId(hwnd, out int processId);
                
                var windowTitle = new StringBuilder(256);
                GetWindowText(hwnd, windowTitle, windowTitle.Capacity);
                
                try
                {
                    var process = Process.GetProcessById(processId);
                    return (windowTitle.ToString(), process.ProcessName, processId);
                }
                catch
                {
                    return (windowTitle.ToString(), "Unknown", processId);
                }
            }
            catch
            {
                return ("Unknown", "Unknown", 0);
            }
        }

        private double GetAppForegroundTime(string appName)
        {
            if (_appStartTimes.ContainsKey(appName))
                return (DateTime.Now - _appStartTimes[appName]).TotalSeconds;
            return 0;
        }

        private double GetSystemCpuUsage()
        {
            try
            {
                using var pc = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                pc.NextValue();
                System.Threading.Thread.Sleep(100);
                return pc.NextValue();
            }
            catch
            {
                return 0;
            }
        }

        private double GetSystemMemoryUsage()
        {
            try
            {
                using var pc = new PerformanceCounter("Memory", "Available MBytes");
                var availableMB = pc.NextValue();
                var totalMB = GC.GetTotalMemory(false) / (1024 * 1024);
                return totalMB;
            }
            catch
            {
                return 0;
            }
        }

        private double GetProcessCpuUsage(int processId)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.HasExited) return 0;
                return process.TotalProcessorTime.TotalMilliseconds;
            }
            catch
            {
                return 0;
            }
        }

        private long GetProcessMemoryUsage(int processId)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.HasExited) return 0;
                return process.WorkingSet64 / (1024 * 1024); // MB
            }
            catch
            {
                return 0;
            }
        }

        private int GetProcessCountByName(string processName)
        {
            try
            {
                return Process.GetProcessesByName(processName).Length;
            }
            catch
            {
                return 0;
            }
        }

        private List<Process> GetSafeProcessList(Process[] processes)
        {
            var safeProcesses = new List<Process>();
            foreach (var process in processes)
            {
                try
                {
                    if (!process.HasExited && !string.IsNullOrEmpty(process.MainWindowTitle))
                    {
                        safeProcesses.Add(process);
                    }
                }
                catch
                {
                    // Skip processes we can't access
                }
            }
            return safeProcesses;
        }
    }
}