using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacMfaSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckTouchID(signals);
            await CheckMfaApps(signals);
            
            return signals;
        }

        private async Task CheckTouchID(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("bioutil", "-r");
                if (output.Contains("Touch ID for"))
                {
                    // TouchID is configured
                }
                else
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.MFA_SECURITY,
                        Security = "MFA NOT CONFIGURED",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckMfaApps(List<SignalCapture> signals)
        {
            try
            {
                var mfaApps = new[] { "Authy", "Google Authenticator", "Microsoft Authenticator" };
                foreach (var app in mfaApps)
                {
                    var output = await RunCommandAsync("find", $"/Applications -name '*{app}*' -type d");
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        signals.Add(new SignalCapture
                        {
                            Type = SignalTypes.MFA_SECURITY,
                            Security = "UNAUTHORIZED MFA APP",
                            ProcessName = app,
                            HipaaViolation = true,
                            Timestamp = DateTime.Now
                        });
                    }
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