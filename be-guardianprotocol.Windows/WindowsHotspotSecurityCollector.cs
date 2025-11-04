using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace be_guardianprotocol.Windows
{
    public class WindowsHotspotSecurityCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private readonly HotspotSecurityConfig _config;

        public WindowsHotspotSecurityCollector()
        {
            _logger = new NetworkConnectionLogger();
            _config = LoadConfig();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var hotspotDetection = await DetectHotspotActivityAsync();
                var tetheringDetection = await DetectTetheringAsync();
                var networkSharingDetection = await DetectNetworkSharingAsync();

                if (hotspotDetection.IsActive || tetheringDetection.IsActive || networkSharingDetection.IsActive)
                {
                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.HOTSPOT_SECURITY,
                        IsConnected = hotspotDetection.IsActive || tetheringDetection.IsActive,
                        Timestamp = DateTime.Now,
                        Security = BuildSecurityMessage(hotspotDetection, tetheringDetection, networkSharingDetection),
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.312(e)(1) & 164.312(a)(1)",
                        MitreTactic = "Command & Control, Defense Evasion, Exfiltration",
                        MitreTechnique = "T1571 - Non-Standard Port, T1562.004 - Network Boundary Evasion, T1048 - Exfiltration Over Alternate Channel",
                        ThreatDetected = "AN0212 - Exfiltration Over Alternate Network Interfaces",
                        VpnConnectionCount = hotspotDetection.ConnectedDevices + tetheringDetection.ConnectedDevices
                    };

                    await _logger.LogConnectionAsync(capture);
                    results.Add(capture);
                }
            }
            catch (Exception ex)
            {
                var errorCapture = new SignalCapture
                {
                    Type = SignalTypes.HOTSPOT_SECURITY,
                    IsConnected = false,
                    Timestamp = DateTime.Now,
                    ErrorMessage = ex.Message
                };
                results.Add(errorCapture);
            }

            return results;
        }

        private async Task<HotspotDetection> DetectHotspotActivityAsync()
        {
            var detection = new HotspotDetection();

            try
            {
                // Check Windows Mobile Hotspot service
                var mobileHotspotStatus = await CheckMobileHotspotServiceAsync();
                detection.IsActive = mobileHotspotStatus.IsRunning;
                detection.ServiceName = mobileHotspotStatus.ServiceName;

                // Check for hosted network via netsh
                var hostedNetworkInfo = await GetHostedNetworkInfoAsync();
                if (hostedNetworkInfo.IsEnabled)
                {
                    detection.IsActive = true;
                    detection.SSID = hostedNetworkInfo.SSID;
                    detection.ConnectedDevices = hostedNetworkInfo.ClientCount;
                }

                // Check network adapters for hotspot interfaces
                var hotspotAdapters = GetHotspotNetworkAdapters();
                if (hotspotAdapters.Any())
                {
                    detection.IsActive = true;
                    detection.InterfaceNames.AddRange(hotspotAdapters.Select(a => a.Name));
                }
            }
            catch { /* Silent fail */ }

            return detection;
        }

        private async Task<TetheringDetection> DetectTetheringAsync()
        {
            var detection = new TetheringDetection();

            try
            {
                // Check for tethering processes
                var tetheringProcesses = GetTetheringProcesses();
                detection.IsActive = tetheringProcesses.Any();
                detection.ProcessNames.AddRange(tetheringProcesses.Select(p => p.ProcessName));

                // Check USB tethering via network adapters
                var usbTetheringAdapters = GetUSBTetheringAdapters();
                if (usbTetheringAdapters.Any())
                {
                    detection.IsActive = true;
                    detection.USBTetheringDetected = true;
                    detection.ConnectedDevices = usbTetheringAdapters.Count;
                }

                // Check Bluetooth tethering
                var bluetoothTethering = await CheckBluetoothTetheringAsync();
                if (bluetoothTethering)
                {
                    detection.IsActive = true;
                    detection.BluetoothTetheringDetected = true;
                }
            }
            catch { /* Silent fail */ }

            return detection;
        }

        private async Task<NetworkSharingDetection> DetectNetworkSharingAsync()
        {
            var detection = new NetworkSharingDetection();

            try
            {
                // Check Internet Connection Sharing service
                var icsStatus = await CheckICSServiceAsync();
                detection.IsActive = icsStatus.IsRunning;
                detection.ICSEnabled = icsStatus.IsRunning;

                // Check for network bridging
                var bridgedAdapters = GetBridgedNetworkAdapters();
                if (bridgedAdapters.Any())
                {
                    detection.IsActive = true;
                    detection.NetworkBridgingDetected = true;
                    detection.BridgedInterfaces.AddRange(bridgedAdapters.Select(a => a.Name));
                }
            }
            catch { /* Silent fail */ }

            return detection;
        }

        private async Task<ServiceStatus> CheckMobileHotspotServiceAsync()
        {
            try
            {
                var service = ServiceController.GetServices()
                    .FirstOrDefault(s => s.ServiceName.Equals("icssvc", StringComparison.OrdinalIgnoreCase));

                if (service != null)
                {
                    return new ServiceStatus
                    {
                        ServiceName = service.ServiceName,
                        IsRunning = service.Status == ServiceControllerStatus.Running
                    };
                }
            }
            catch { /* Silent fail */ }

            return new ServiceStatus();
        }

        private async Task<HostedNetworkInfo> GetHostedNetworkInfoAsync()
        {
            var info = new HostedNetworkInfo();

            try
            {
                var netshOutput = await RunCommandAsync("netsh", "wlan show hostednetwork");
                
                if (netshOutput.Contains("Status") && netshOutput.Contains("Started"))
                {
                    info.IsEnabled = true;
                    
                    var ssidMatch = Regex.Match(netshOutput, @"SSID name\s*:\s*""([^""]+)""");
                    if (ssidMatch.Success)
                        info.SSID = ssidMatch.Groups[1].Value;

                    var clientMatch = Regex.Match(netshOutput, @"Number of clients\s*:\s*(\d+)");
                    if (clientMatch.Success && int.TryParse(clientMatch.Groups[1].Value, out var clientCount))
                        info.ClientCount = clientCount;
                }
            }
            catch { /* Silent fail */ }

            return info;
        }

        private List<NetworkInterface> GetHotspotNetworkAdapters()
        {
            var hotspotAdapters = new List<NetworkInterface>();

            try
            {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in adapters)
                {
                    var name = adapter.Name.ToLower();
                    var description = adapter.Description.ToLower();
                    
                    if ((name.Contains("hotspot") || name.Contains("hosted") || 
                         description.Contains("microsoft wi-fi direct virtual adapter") ||
                         description.Contains("microsoft hosted network virtual adapter")) &&
                        adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        hotspotAdapters.Add(adapter);
                    }
                }
            }
            catch { /* Silent fail */ }

            return hotspotAdapters;
        }

        private List<Process> GetTetheringProcesses()
        {
            var tetheringProcesses = new List<Process>();

            try
            {
                var processes = Process.GetProcesses();
                var tetheringNames = _config.TetheringProcessNames;

                foreach (var process in processes)
                {
                    try
                    {
                        if (tetheringNames.Any(name => 
                            process.ProcessName.ToLower().Contains(name.ToLower())))
                        {
                            tetheringProcesses.Add(process);
                        }
                    }
                    catch { /* Skip processes we can't access */ }
                }
            }
            catch { /* Silent fail */ }

            return tetheringProcesses;
        }

        private List<NetworkInterface> GetUSBTetheringAdapters()
        {
            var usbAdapters = new List<NetworkInterface>();

            try
            {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in adapters)
                {
                    var description = adapter.Description.ToLower();
                    
                    if ((description.Contains("remote ndis") || 
                         description.Contains("usb ethernet") ||
                         description.Contains("android") ||
                         description.Contains("iphone")) &&
                        adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        usbAdapters.Add(adapter);
                    }
                }
            }
            catch { /* Silent fail */ }

            return usbAdapters;
        }

        private async Task<bool> CheckBluetoothTetheringAsync()
        {
            try
            {
                var btOutput = await RunCommandAsync("powershell", 
                    "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*Bluetooth*' -and $_.Status -eq 'Up'}");
                
                return !string.IsNullOrEmpty(btOutput) && btOutput.Contains("Bluetooth");
            }
            catch
            {
                return false;
            }
        }

        private async Task<ServiceStatus> CheckICSServiceAsync()
        {
            try
            {
                var service = ServiceController.GetServices()
                    .FirstOrDefault(s => s.ServiceName.Equals("SharedAccess", StringComparison.OrdinalIgnoreCase));

                if (service != null)
                {
                    return new ServiceStatus
                    {
                        ServiceName = service.ServiceName,
                        IsRunning = service.Status == ServiceControllerStatus.Running
                    };
                }
            }
            catch { /* Silent fail */ }

            return new ServiceStatus();
        }

        private List<NetworkInterface> GetBridgedNetworkAdapters()
        {
            var bridgedAdapters = new List<NetworkInterface>();

            try
            {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in adapters)
                {
                    if (adapter.Description.ToLower().Contains("bridge") &&
                        adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        bridgedAdapters.Add(adapter);
                    }
                }
            }
            catch { /* Silent fail */ }

            return bridgedAdapters;
        }

        private string BuildSecurityMessage(HotspotDetection hotspot, TetheringDetection tethering, NetworkSharingDetection sharing)
        {
            var messages = new List<string>();

            if (hotspot.IsActive)
            {
                messages.Add($"UNAUTHORIZED HOTSPOT: {hotspot.SSID} ({hotspot.ConnectedDevices} clients)");
            }

            if (tethering.USBTetheringDetected)
            {
                messages.Add($"USB TETHERING: {tethering.ConnectedDevices} devices");
            }

            if (tethering.BluetoothTetheringDetected)
            {
                messages.Add("BLUETOOTH TETHERING");
            }

            if (sharing.ICSEnabled)
            {
                messages.Add("INTERNET CONNECTION SHARING");
            }

            if (sharing.NetworkBridgingDetected)
            {
                messages.Add($"NETWORK BRIDGING: {sharing.BridgedInterfaces.Count} interfaces");
            }

            if (tethering.ProcessNames.Any())
            {
                messages.Add($"TETHERING PROCESSES: {string.Join(", ", tethering.ProcessNames)}");
            }

            return string.Join(" | ", messages);
        }

        private async Task<string> RunCommandAsync(string cmd, string args)
        {
            try
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
            catch
            {
                return "";
            }
        }

        private HotspotSecurityConfig LoadConfig()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hotspot-security-config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<HotspotSecurityConfig>(json) ?? new HotspotSecurityConfig();
                }
            }
            catch { /* Silent fail */ }

            return new HotspotSecurityConfig();
        }
    }

    public class HotspotSecurityConfig
    {
        public List<string> TetheringProcessNames { get; set; } = new()
        {
            "hotspot", "tether", "pdanet", "foxfi", "easytether", "connectify"
        };
    }

    public class HotspotDetection
    {
        public bool IsActive { get; set; }
        public string SSID { get; set; } = "";
        public string ServiceName { get; set; } = "";
        public int ConnectedDevices { get; set; }
        public List<string> InterfaceNames { get; set; } = new();
    }

    public class TetheringDetection
    {
        public bool IsActive { get; set; }
        public bool USBTetheringDetected { get; set; }
        public bool BluetoothTetheringDetected { get; set; }
        public int ConnectedDevices { get; set; }
        public List<string> ProcessNames { get; set; } = new();
    }

    public class NetworkSharingDetection
    {
        public bool IsActive { get; set; }
        public bool ICSEnabled { get; set; }
        public bool NetworkBridgingDetected { get; set; }
        public List<string> BridgedInterfaces { get; set; } = new();
    }

    public class ServiceStatus
    {
        public string ServiceName { get; set; } = "";
        public bool IsRunning { get; set; }
    }

    public class HostedNetworkInfo
    {
        public bool IsEnabled { get; set; }
        public string SSID { get; set; } = "";
        public int ClientCount { get; set; }
    }
}