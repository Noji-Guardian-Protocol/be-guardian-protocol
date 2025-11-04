using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;

namespace be_guardianprotocol.Windows
{
    public class WindowsBluetoothCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;

        public WindowsBluetoothCollector()
        {
            _logger = new NetworkConnectionLogger();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var bluetoothDevices = await GetBluetoothDevicesAsync();
                
                var capture = new SignalCapture
                {
                    Type = SignalTypes.Bluetooth,
                    IsConnected = bluetoothDevices.Any(),
                    Timestamp = DateTime.Now,
                    DeviceCount = bluetoothDevices.Count,
                    ConnectedDevices = string.Join(";", bluetoothDevices.Select(d => d.Name)),
                    BluetoothEnabled = await IsBluetoothEnabledAsync(),
                    NearbyDeviceCount = bluetoothDevices.Count(d => d.IsConnected),
                    PairedDeviceCount = bluetoothDevices.Count(d => d.IsPaired)
                };

                await _logger.LogConnectionAsync(capture);
                results.Add(capture);
            }
            catch (Exception ex)
            {
                var errorCapture = new SignalCapture
                {
                    Type = SignalTypes.Bluetooth,
                    IsConnected = false,
                    Timestamp = DateTime.Now,
                    ErrorMessage = ex.Message
                };
                results.Add(errorCapture);
            }

            return results;
        }

        private async Task<List<BluetoothDevice>> GetBluetoothDevicesAsync()
        {
            var devices = new List<BluetoothDevice>();

            try
            {
                var output = await RunCommandAsync("powershell", 
                    "Get-PnpDevice | Where-Object {$_.Class -eq 'Bluetooth'} | Select-Object FriendlyName, Status, InstanceId | ConvertTo-Json");

                if (!string.IsNullOrEmpty(output))
                {
                    // Parse PowerShell JSON output for Bluetooth devices
                    var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (line.Contains("FriendlyName") && line.Contains(":"))
                        {
                            var name = ExtractValue(line, "FriendlyName");
                            var status = ExtractValue(output, "Status");
                            
                            devices.Add(new BluetoothDevice
                            {
                                Name = name,
                                IsConnected = status?.Contains("OK") == true,
                                IsPaired = true // Assume paired if showing in PnP devices
                            });
                        }
                    }
                }
            }
            catch
            {
                // Fallback to WMI query
                try
                {
                    var wmiOutput = await RunCommandAsync("wmic", 
                        "path Win32_PnPEntity where \"PNPClass='Bluetooth'\" get Name,Status /format:csv");
                    
                    var lines = wmiOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines.Skip(1))
                    {
                        var parts = line.Split(',');
                        if (parts.Length >= 3 && !string.IsNullOrWhiteSpace(parts[1]))
                        {
                            devices.Add(new BluetoothDevice
                            {
                                Name = parts[1].Trim(),
                                IsConnected = parts[2]?.Trim() == "OK",
                                IsPaired = true
                            });
                        }
                    }
                }
                catch { /* Silent fail */ }
            }

            return devices;
        }

        private async Task<bool> IsBluetoothEnabledAsync()
        {
            try
            {
                var output = await RunCommandAsync("powershell", 
                    "Get-Service -Name 'bthserv' | Select-Object Status");
                return output.Contains("Running");
            }
            catch
            {
                return false;
            }
        }

        private string ExtractValue(string json, string key)
        {
            var keyIndex = json.IndexOf($"\"{key}\":");
            if (keyIndex == -1) return "";
            
            var valueStart = json.IndexOf("\"", keyIndex + key.Length + 3);
            if (valueStart == -1) return "";
            
            var valueEnd = json.IndexOf("\"", valueStart + 1);
            if (valueEnd == -1) return "";
            
            return json.Substring(valueStart + 1, valueEnd - valueStart - 1);
        }

        private async Task<string> RunCommandAsync(string cmd, string args)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = cmd,
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

    public class BluetoothDevice
    {
        public string Name { get; set; } = "";
        public bool IsConnected { get; set; }
        public bool IsPaired { get; set; }
    }
}