using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacPasswordExpirationCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckPasswordAge(signals);
            
            return signals;
        }

        private async Task CheckPasswordAge(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("dscl", ". -read /Users/$USER passwordpolicyoptions");
                if (output.Contains("maxMinutesUntilChangePassword"))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.PASSWORD_EXPIRATION,
                        Security = "PASSWORD EXPIRATION WARNING",
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