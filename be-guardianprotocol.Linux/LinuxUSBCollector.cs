using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxUSBCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckUSBDevices(signals);
            
            return signals;
        }

        private async Task CheckUSBDevices(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("lsusb", "| grep -v 'Linux Foundation' | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count > 0)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.USB,
                        DeviceCount = count,
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