using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxCloudStorageCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckCloudServices(signals);
            
            return signals;
        }

        private async Task CheckCloudServices(List<SignalCapture> signals)
        {
            try
            {
                var cloudApps = new[] { "dropbox", "google-drive", "onedrive", "nextcloud" };
                foreach (var app in cloudApps)
                {
                    var output = await RunCommandAsync("ps", $"aux | grep {app} | grep -v grep | wc -l");
                    if (int.TryParse(output.Trim(), out var count) && count > 0)
                    {
                        signals.Add(new SignalCapture
                        {
                            Type = SignalTypes.UNAUTHORIZED_CLOUD_STORAGE,
                            Security = "UNAPPROVED CLOUD SERVICE",
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