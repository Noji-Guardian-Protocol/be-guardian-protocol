using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxEndpointProtectionCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckFirewall(signals);
            await CheckAppArmor(signals);
            await CheckSELinux(signals);
            
            return signals;
        }

        private async Task CheckFirewall(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("ufw", "status | grep Status | awk '{print $2}'");
                if (output.Trim() == "inactive")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "ENDPOINT PROTECTION DISABLED",
                        ProcessName = "ufw",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckAppArmor(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("systemctl", "is-active apparmor");
                if (output.Trim() != "active")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "ENDPOINT PROTECTION DISABLED",
                        ProcessName = "apparmor",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckSELinux(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("getenforce", "2>/dev/null || echo Disabled");
                if (output.Trim() == "Disabled")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "ENDPOINT PROTECTION DISABLED",
                        ProcessName = "selinux",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
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