using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacApplicationSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckUnsignedApplications(signals);
            await CheckExternalRepositories(signals);
            await CheckPolicyViolations(signals);
            
            return signals;
        }

        private async Task CheckUnsignedApplications(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("find", "/Applications -name '*.app' -exec codesign -dv {} \\; 2>&1");
                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                
                foreach (var line in lines)
                {
                    if (line.Contains("code object is not signed"))
                    {
                        signals.Add(new SignalCapture
                        {
                            Type = SignalTypes.Process,
                            Security = "UNSIGNED SOFTWARE",
                            ProcessName = ExtractAppName(line),
                            HipaaViolation = true,
                            ComplianceRule = "HIPAA 164.308(a)(1)",
                            Timestamp = DateTime.Now
                        });
                    }
                }
            }
            catch { }
        }

        private async Task CheckExternalRepositories(List<SignalCapture> signals)
        {
            try
            {
                var brewOutput = await RunCommandAsync("brew", "list --cask 2>/dev/null || echo 'none'");
                if (!brewOutput.Contains("none"))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "EXTERNAL REPOSITORY",
                        ProcessName = "Homebrew",
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.308(a)(1)",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckPolicyViolations(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("spctl", "--status");
                if (output.Contains("disabled"))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        Security = "POLICY BYPASS",
                        ProcessName = "Gatekeeper",
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.308(a)(1)",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private string ExtractAppName(string line)
        {
            var parts = line.Split('/');
            return parts.LastOrDefault(p => p.EndsWith(".app"))?.Replace(".app", "") ?? "Unknown";
        }

        private async Task<string> RunCommandAsync(string command, string args)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = args,
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