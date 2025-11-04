using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxWifiCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            try
            {
                var output = await RunCommandAsync("nmcli", "-f SSID,SIGNAL dev wifi list");
                signals = ParseOutput(output);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Linux] Wi-Fi scan failed: {ex.Message}");
            }
            return signals;
        }

        private static List<SignalCapture> ParseOutput(string output)
        {
            var readings = new List<SignalCapture>();
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1);

            foreach (var line in lines)
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                readings.Add(new SignalCapture
                {
                    Type = SignalTypes.Wifi,
                    Name = parts[0],
                    Strength = double.TryParse(parts[^1], out var s) ? s : 0
                });
            }

            return readings;
        }

        private static async Task<string> RunCommandAsync(string command, string args)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = args,
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
