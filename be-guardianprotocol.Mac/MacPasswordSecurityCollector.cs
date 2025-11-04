using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacPasswordSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckPasswordPolicy(signals);
            await CheckFailedLogins(signals);
            
            return signals;
        }

        private async Task CheckPasswordPolicy(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("pwpolicy", "-getaccountpolicies");
                if (output.Contains("minChars") && output.Contains("8"))
                {
                    // Password policy exists
                }
                else
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.PASSWORD_SECURITY,
                        Security = "WEAK PASSWORD PATTERN",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckFailedLogins(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("log", "show --predicate 'eventMessage contains \"Authentication failure\"' --last 1h | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count > 5)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.PASSWORD_SECURITY,
                        Security = "BRUTE FORCE",
                        FailedLogonCount = count,
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