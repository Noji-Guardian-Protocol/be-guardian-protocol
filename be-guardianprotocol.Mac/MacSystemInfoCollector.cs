using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacSystemInfoCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var systemInfo = await GetSystemInfo();
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.SYSTEM_INFO,
                ProcessName = "SystemInfo",
                ProcessPath = systemInfo,
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<string> GetSystemInfo()
        {
            try
            {
                var model = await RunCommandAsync("system_profiler", "SPHardwareDataType | grep 'Model Name' | cut -d: -f2 | xargs");
                var arch = await RunCommandAsync("uname", "-m");
                var os = await RunCommandAsync("sw_vers", "-productVersion");
                
                return $"Model: {model.Trim()}, Architecture: {arch.Trim()}, macOS: {os.Trim()}";
            }
            catch
            {
                return "Unknown Mac System";
            }
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