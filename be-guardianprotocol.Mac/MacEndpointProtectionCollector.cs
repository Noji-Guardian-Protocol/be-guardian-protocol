using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacEndpointProtectionCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckXProtect(signals);
            await CheckGatekeeper(signals);
            await CheckSIP(signals);
            
            return signals;
        }

        private async Task CheckXProtect(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("system_profiler", "SPInstallHistoryDataType | grep 'XProtect'");
                if (string.IsNullOrWhiteSpace(output))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "ENDPOINT PROTECTION DISABLED",
                        ProcessName = "XProtect",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckGatekeeper(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("spctl", "--status");
                if (output.Contains("disabled"))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "ENDPOINT PROTECTION DISABLED",
                        ProcessName = "Gatekeeper",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckSIP(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("csrutil", "status");
                if (output.Contains("disabled"))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "ENDPOINT PROTECTION DISABLED",
                        ProcessName = "SIP",
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