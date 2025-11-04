using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxApplicationSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckUnsignedPackages(signals);
            await CheckExternalRepositories(signals);
            await CheckSnapPackages(signals);
            
            return signals;
        }

        private async Task CheckUnsignedPackages(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("dpkg", "-l | grep -v '^ii' | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count > 0)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "UNSIGNED SOFTWARE",
                        ProcessName = "dpkg",
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.308(a)(1)",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckExternalRepositories(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("apt", "policy | grep -v 'ubuntu\\|debian' | grep http | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count > 0)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "EXTERNAL REPOSITORY",
                        ProcessName = "apt",
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.308(a)(1)",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckSnapPackages(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("snap", "list 2>/dev/null | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count > 1)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "EXTERNAL REPOSITORY",
                        ProcessName = "snap",
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.308(a)(1)",
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