using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacUSBCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckUSBDevices(signals);
            await CheckDataTransfers(signals);
            
            return signals;
        }

        private async Task CheckUSBDevices(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("system_profiler", "SPUSBDataType | grep 'Product ID'");
                var deviceCount = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
                
                if (deviceCount > 0)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.USB,
                        Security = "USB_DEVICES",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckDataTransfers(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("lsof", "| grep /Volumes | wc -l");
                if (int.TryParse(output.Trim(), out var transfers) && transfers > 0)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.USB,
                        Security = "DATA_TRANSFER",
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