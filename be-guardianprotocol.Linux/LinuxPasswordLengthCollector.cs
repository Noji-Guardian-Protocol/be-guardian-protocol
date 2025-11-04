using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxPasswordLengthCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckPasswordLength(signals);
            
            return signals;
        }

        private async Task CheckPasswordLength(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("grep", "^PASS_MIN_LEN /etc/login.defs | awk '{print $2}'");
                if (int.TryParse(output.Trim(), out var minLen) && minLen < 8)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.PASSWORD_LENGTH_SECURITY,
                        Security = "POLICY VIOLATION",
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