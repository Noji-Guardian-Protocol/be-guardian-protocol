using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxSystemInfoCollector : ISignalCollector
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
                var distro = await RunCommandAsync("lsb_release", "-d | cut -f2");
                var kernel = await RunCommandAsync("uname", "-r");
                var arch = await RunCommandAsync("uname", "-m");
                
                return $"Distro: {distro.Trim()}, Kernel: {kernel.Trim()}, Arch: {arch.Trim()}";
            }
            catch
            {
                return "Unknown Linux System";
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