using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacProcessCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var processCount = await GetProcessCount();
            var currentApp = await GetCurrentApp();
            var systemStats = await GetSystemStats();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Process,
                Security = $"Processes: {processCount}, Current: {currentApp}, {systemStats}",
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
                var output = await RunCommandAsync("osascript", "-e 'tell application \"System Events\" to get name of first application process whose frontmost is true'");
                return output.Trim();
            }
            catch { return "Unknown"; }
        }

        private async Task<string> GetSystemStats()
        {
            try
            {
                var cpu = await RunCommandAsync("top", "-l 1 -n 0 | grep 'CPU usage' | awk '{print $3}' | sed 's/%//'");
                var mem = await RunCommandAsync("vm_stat", "| grep 'Pages free' | awk '{print $3}' | sed 's/\\.//'");
                return $"CPU: {cpu.Trim()}%, Memory: {mem.Trim()}";
            }
            catch { return "Stats unavailable"; }
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