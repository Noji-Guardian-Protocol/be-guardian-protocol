using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxMfaSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckPamMfa(signals);
            
            return signals;
        }

        private async Task CheckPamMfa(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("grep", "pam_google_authenticator /etc/pam.d/common-auth 2>/dev/null | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count == 0)
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