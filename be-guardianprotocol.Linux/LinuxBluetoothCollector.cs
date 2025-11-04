using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxBluetoothCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var bluetoothStatus = await CheckBluetoothStatus();
            var deviceCount = await GetConnectedDevices();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Bluetooth,
                BluetoothEnabled = bluetoothStatus,
                DeviceCount = deviceCount,
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<bool> CheckBluetoothStatus()
        {
            try
            {
                var output = await RunCommandAsync("bluetoothctl", "show | grep Powered | awk '{print $2}'");
                return output.Trim() == "yes";
            }
            catch { return false; }
        }

        private async Task<int> GetConnectedDevices()
        {
            try
            {
                var output = await RunCommandAsync("bluetoothctl", "devices Connected | wc -l");
                return int.TryParse(output.Trim(), out var count) ? count : 0;
            }
            catch { return 0; }
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