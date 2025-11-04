using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Text.Json;
using System.IO;

namespace be_guardianprotocol.Windows
{
    public class WindowsUSBCollector : ISignalCollector
    {
        private static readonly NetworkConnectionLogger _logger = new();
        private static readonly HashSet<string> _knownDevices = new();
        private static readonly Dictionary<string, DateTime> _deviceMountTimes = new();
        private static readonly string[] _sensitiveExtensions = [".docx", ".pdf", ".xlsx", ".pptx", ".txt", ".csv", ".db", ".sql", ".xml", ".json"];

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            // Get USB devices using WMI
            var usbOutput = await RunCommandAsync("wmic", "path Win32_USBHub get DeviceID,Name,Status /format:csv");
            var usbDevices = ParseUSBDevices(usbOutput);
            results.AddRange(usbDevices);

            // Get PnP devices for more details
            var pnpOutput = await RunCommandAsync("wmic", "path Win32_PnPEntity where \"DeviceID like '%USB%'\" get DeviceID,Name,Status,Manufacturer /format:csv");
            var pnpDevices = ParsePnPDevices(pnpOutput);
            results.AddRange(pnpDevices);
            
            // Monitor removable drives for data exfiltration
            await MonitorRemovableDrives(results);
            
            // Check for unauthorized devices
            CheckUnauthorizedDevices(results);

            // Log all USB events
            foreach (var device in results)
            {
                await _logger.LogConnectionAsync(device);
            }

            return results;
        }

        private static List<SignalCapture> ParseUSBDevices(string output)
        {
            var devices = new List<SignalCapture>();
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines.Skip(1))
            {
                var parts = line.Split(',');
                if (parts.Length >= 4 && !string.IsNullOrWhiteSpace(parts[1]))
                {
                    var deviceId = parts[1].Trim();
                    var name = parts[2].Trim();
                    var status = parts[3].Trim();

                    var isNewDevice = !_knownDevices.Contains(deviceId);
                    if (isNewDevice) _knownDevices.Add(deviceId);

                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.USB,
                        Name = name,
                        USBDeviceID = deviceId,
                        IsConnected = status.Equals("OK", StringComparison.OrdinalIgnoreCase),
                        EventType = isNewDevice ? "Connected" : "Present",
                        ConnectionTime = isNewDevice ? DateTime.Now : null
                    };

                    // Extract VID/PID from device ID
                    ExtractVendorProductIDs(deviceId, capture);
                    
                    // Determine device class
                    capture.DeviceClass = DetermineDeviceClass(name);
                    capture.PowerState = capture.IsConnected ? "Active" : "Inactive";

                    devices.Add(capture);
                }
            }

            return devices;
        }

        private static List<SignalCapture> ParsePnPDevices(string output)
        {
            var devices = new List<SignalCapture>();
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines.Skip(1))
            {
                var parts = line.Split(',');
                if (parts.Length >= 5 && !string.IsNullOrWhiteSpace(parts[1]))
                {
                    var deviceId = parts[1].Trim();
                    var manufacturer = parts[2].Trim();
                    var name = parts[3].Trim();
                    var status = parts[4].Trim();

                    // Skip if already processed as USB Hub
                    if (_knownDevices.Contains(deviceId)) continue;

                    var isNewDevice = !_knownDevices.Contains(deviceId);
                    if (isNewDevice) _knownDevices.Add(deviceId);

                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.USB,
                        Name = $"{manufacturer} {name}".Trim(),
                        USBDeviceID = deviceId,
                        IsConnected = status.Equals("OK", StringComparison.OrdinalIgnoreCase),
                        EventType = isNewDevice ? "Connected" : "Present",
                        ConnectionTime = isNewDevice ? DateTime.Now : null
                    };

                    // Extract VID/PID from device ID
                    ExtractVendorProductIDs(deviceId, capture);
                    
                    // Determine device class and transfer speed
                    capture.DeviceClass = DetermineDeviceClass(name);
                    capture.TransferSpeed = DetermineUSBSpeed(deviceId);
                    capture.PowerState = capture.IsConnected ? "Active" : "Inactive";

                    devices.Add(capture);
                }
            }

            return devices;
        }

        private static void ExtractVendorProductIDs(string deviceId, SignalCapture capture)
        {
            try
            {
                if (deviceId.Contains("VID_") && deviceId.Contains("PID_"))
                {
                    var vidStart = deviceId.IndexOf("VID_") + 4;
                    var pidStart = deviceId.IndexOf("PID_") + 4;
                    
                    capture.VendorID = deviceId.Substring(vidStart, 4);
                    capture.ProductID = deviceId.Substring(pidStart, 4);
                }
            }
            catch
            {
                // Silent fail for ID extraction
            }
        }

        private static string DetermineDeviceClass(string name)
        {
            var lowerName = name.ToLower();
            if (lowerName.Contains("mouse") || lowerName.Contains("keyboard")) return "HID";
            if (lowerName.Contains("storage") || lowerName.Contains("disk")) return "Storage";
            if (lowerName.Contains("camera") || lowerName.Contains("webcam")) return "Video";
            if (lowerName.Contains("audio") || lowerName.Contains("speaker")) return "Audio";
            if (lowerName.Contains("printer")) return "Printer";
            if (lowerName.Contains("hub")) return "Hub";
            if (lowerName.Contains("network") || lowerName.Contains("ethernet")) return "Network";
            return "Unknown";
        }

        private static string DetermineUSBSpeed(string deviceId)
        {
            if (deviceId.Contains("USB\\VID_")) return "USB 2.0";
            if (deviceId.Contains("USB3")) return "USB 3.0";
            if (deviceId.Contains("USBSTOR")) return "USB 2.0";
            return "Unknown";
        }

        private static async Task MonitorRemovableDrives(List<SignalCapture> results)
        {
            try
            {
                var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable && d.IsReady).ToList();
                
                foreach (var drive in drives)
                {
                    var driveLetter = drive.Name.Substring(0, 2);
                    
                    // Track drive mount time
                    if (!_deviceMountTimes.ContainsKey(driveLetter))
                        _deviceMountTimes[driveLetter] = DateTime.Now;
                    
                    // Check for recent file transfers
                    var recentFiles = GetRecentFileTransfers(drive.RootDirectory);
                    
                    if (recentFiles.Any())
                    {
                        var sensitiveFiles = recentFiles.Where(f => _sensitiveExtensions.Any(ext => 
                            f.Name.EndsWith(ext, StringComparison.OrdinalIgnoreCase))).ToList();
                        
                        var capture = new SignalCapture
                        {
                            Type = SignalTypes.USB,
                            Name = $"Removable Drive {driveLetter}",
                            USBDeviceID = driveLetter,
                            IsConnected = true,
                            EventType = "Data Transfer",
                            DeviceClass = "Storage",
                            Security = sensitiveFiles.Any() ? "🚨 SENSITIVE DATA TRANSFER" : "📁 File Transfer",
                            HipaaViolation = sensitiveFiles.Any(),
                            ComplianceRule = sensitiveFiles.Any() ? "HIPAA 164.310(d)(1) & 164.312(a)(1)" : null,
                            MitreTactic = sensitiveFiles.Any() ? "Exfiltration" : null,
                            MitreTechnique = sensitiveFiles.Any() ? "T1052 - Exfiltration to Physical Medium" : null,
                            ThreatDetected = sensitiveFiles.Any() ? "AN0841 - Sensitive Data to Removable Media" : null
                        };
                        
                        if (sensitiveFiles.Any())
                        {
                            capture.Security += $" - {sensitiveFiles.Count} sensitive files";
                        }
                        
                        await _logger.LogConnectionAsync(capture);
                        results.Add(capture);
                    }
                }
            }
            catch { }
        }
        
        private static List<FileInfo> GetRecentFileTransfers(DirectoryInfo directory)
        {
            try
            {
                var cutoffTime = DateTime.Now.AddMinutes(-5);
                return directory.GetFiles("*", SearchOption.TopDirectoryOnly)
                    .Where(f => f.CreationTime > cutoffTime || f.LastWriteTime > cutoffTime)
                    .ToList();
            }
            catch
            {
                return new List<FileInfo>();
            }
        }
        
        private static void CheckUnauthorizedDevices(List<SignalCapture> results)
        {
            var config = GetUSBSecurityConfig();
            
            foreach (var device in results.Where(d => d.EventType == "Connected"))
            {
                var isAuthorized = config.AuthorizedDevices.Any(auth => 
                    device.VendorID?.Equals(auth.VendorID, StringComparison.OrdinalIgnoreCase) == true &&
                    device.ProductID?.Equals(auth.ProductID, StringComparison.OrdinalIgnoreCase) == true);
                
                if (!isAuthorized && device.DeviceClass == "Storage")
                {
                    device.Security = "⚠️ UNAUTHORIZED STORAGE DEVICE";
                    device.HipaaViolation = true;
                    device.ComplianceRule = "HIPAA 164.310(d)(1) & 164.312(a)(1)";
                    device.MitreTactic = "Collection, Exfiltration";
                    device.MitreTechnique = "T1025 - Data from Removable Media, T1052 - Exfiltration to Physical Medium";
                    device.ThreatDetected = "AN0841 - Unauthorized Removable Storage";
                }
            }
        }
        
        private static USBSecurityConfig GetUSBSecurityConfig()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "usb-security-config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<USBSecurityConfig>(json) ?? new();
                }
            }
            catch { }
            
            return new USBSecurityConfig();
        }
        
        private static async Task<string> RunCommandAsync(string cmd, string args)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = cmd,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };
            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
        
        private class USBSecurityConfig
        {
            public AuthorizedDevice[] AuthorizedDevices { get; set; } = [];
        }
        
        private class AuthorizedDevice
        {
            public string VendorID { get; set; } = "";
            public string ProductID { get; set; } = "";
            public string Description { get; set; } = "";
        }
    }
}