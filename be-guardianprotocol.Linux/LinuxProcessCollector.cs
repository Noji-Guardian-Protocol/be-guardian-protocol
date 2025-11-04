using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxProcessCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var processCount = await GetProcessCount();
            var currentApp = await GetCurrentApp();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Process,
                ActiveProcessCount = processCount,
                CurrentApp = currentApp,
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<int> GetProcessCount()
        {
            try
            {
                var output = await RunCommandAsync("ps", "aux | wc -l");
                return int.TryParse(output.Trim(), out var count) ? count : 0;
            }
            catch { return 0; }
        }

        private async Task<string> GetCurrentApp()
        {
            try
            {
                var output = await RunCommandAsync("xdotool", "getwindowfocus getwindowname 2>/dev/null || echo Unknown");
                return output.Trim();
            }
            catch { return "Unknown"; }
        }

        private async Task<string> RunCommandAsync(string command, string args)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{command} {args}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
    }
}