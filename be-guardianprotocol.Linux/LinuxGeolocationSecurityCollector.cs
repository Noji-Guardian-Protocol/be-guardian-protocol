using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxGeolocationSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckLocationServices(signals);
            
            return signals;
        }

        private async Task CheckLocationServices(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("systemctl", "is-active geoclue 2>/dev/null || echo inactive");
                if (output.Trim() == "active")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.GEOLOCATION_SECURITY,
                        Security = "LOCATION SERVICES ENABLED",
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