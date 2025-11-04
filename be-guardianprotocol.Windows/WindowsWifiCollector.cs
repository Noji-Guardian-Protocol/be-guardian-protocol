using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Text.Json;

namespace be_guardianprotocol.Windows
{
    public class WindowsWifiCollector : ISignalCollector
    {
        private static readonly NetworkConnectionLogger _logger = new();
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            // Only capture connected WiFi
            var connectedOutput = await RunCommandAsync("netsh", "wlan show interfaces");
            var connectedNetwork = ParseConnectedNetwork(connectedOutput);
            if (connectedNetwork != null)
            {
                // Get BSSID from visible networks if not available in interfaces
                if (string.IsNullOrWhiteSpace(connectedNetwork.MacAddress) && !string.IsNullOrWhiteSpace(connectedNetwork.Name))
                {
                    var networksOutput = await RunCommandAsync("netsh", "wlan show networks mode=bssid");
                    var bssid = ExtractBSSIDFromNetworks(networksOutput, connectedNetwork.Name);
                    if (!string.IsNullOrWhiteSpace(bssid))
                        connectedNetwork.MacAddress = bssid;
                }

                // Get IP address for connected network
                var ipOutput = await RunCommandAsync("ipconfig", "/all");
                connectedNetwork.IPAddress = ExtractIPAddress(ipOutput, connectedNetwork.Interface);
                
                // Check for unauthorized network connection
                var isAuthorized = IsAuthorizedNetwork(connectedNetwork.Name);
                var isPublic = IsPublicWiFi(connectedNetwork.Name);
                
                if (!isAuthorized)
                {
                    connectedNetwork.Security += " - 🚫 UNAUTHORIZED NETWORK";
                    connectedNetwork.HipaaViolation = true;
                    connectedNetwork.ComplianceRule = "HIPAA 164.312(a)(1) & 164.312(e)(1)";
                    connectedNetwork.MitreTactic = "Initial Access";
                    connectedNetwork.MitreTechnique = "T1189 - Drive-by Compromise";
                    connectedNetwork.ThreatDetected = "AN1476 - Unauthorized Wi-Fi Connection";
                    
                    if (isPublic)
                    {
                        var vpnActive = await CheckVPNStatus();
                        if (!vpnActive)
                        {
                            connectedNetwork.Security += " - 🔴 VPN INACTIVE";
                            connectedNetwork.MitreTechnique += ", T1040 - Network Sniffing, T1557 - Man-in-the-Middle";
                            connectedNetwork.ThreatDetected = "AN1477 - Public Wi-Fi Without VPN";
                        }
                    }
                }
                
                // Log connection and check for repeated untrusted connections
                await _logger.LogConnectionAsync(connectedNetwork);
                var repeatedAlert = _logger.CheckRepeatedUntrustedConnections(connectedNetwork);
                if (!string.IsNullOrEmpty(repeatedAlert))
                {
                    connectedNetwork.Security += repeatedAlert;
                }
                
                results.Add(connectedNetwork);
            }

            return results;
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
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }

        private static SignalCapture? ParseConnectedNetwork(string output)
        {
            if (string.IsNullOrWhiteSpace(output)) return null;

            var capture = new SignalCapture
            {
                Type = SignalTypes.Wifi,
                IsConnected = true
            };

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmedLine = line.Trim();
                if (trimmedLine.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) && trimmedLine.Contains(":"))
                    capture.Name = trimmedLine.Split(':', 2)[1].Trim();
                else if (trimmedLine.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase) && trimmedLine.Contains(":"))
                    capture.MacAddress = trimmedLine.Split(':', 2)[1].Trim();
                else if (trimmedLine.StartsWith("Signal", StringComparison.OrdinalIgnoreCase))
                    capture.Strength = double.TryParse(trimmedLine.Split(':', 2)[1].Trim().Replace("%", ""), out var s) ? s : null;
                else if (trimmedLine.StartsWith("Radio type", StringComparison.OrdinalIgnoreCase))
                {
                    var radioType = trimmedLine.Split(':', 2)[1].Trim();
                    capture.Frequency = ConvertRadioTypeToFrequency(radioType);
                }
                else if (trimmedLine.StartsWith("Network type", StringComparison.OrdinalIgnoreCase))
                    capture.Mode = trimmedLine.Split(':', 2)[1].Trim();
                else if (trimmedLine.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase))
                {
                    var authType = trimmedLine.Split(':', 2)[1].Trim();
                    var hasWPA2OrWPA3 = HasWPA2OrWPA3(authType);
                    var isAuthorized = IsAuthorizedNetwork(capture.Name);
                    var isPublic = IsPublicWiFi(capture.Name);
                    
                    var securityStatus = hasWPA2OrWPA3 ? "Secure" : "⚠️ ALERT: NO WPA2/WPA3";
                    if (isPublic) securityStatus += " - PUBLIC WIFI";
                    if (!isAuthorized) securityStatus += " - UNAUTHORIZED";
                    
                    // HIPAA compliance and MITRE ATT&CK mapping
                    if (!isAuthorized || !hasWPA2OrWPA3 || isPublic)
                    {
                        securityStatus += " - 🏥 HIPAA VIOLATION";
                        capture.HipaaViolation = true;
                        capture.ComplianceRule = "HIPAA 164.312(a)(1) & 164.312(e)(1)";
                        
                        if (!isAuthorized)
                        {
                            capture.MitreTactic = "Reconnaissance, Initial Access";
                            capture.MitreTechnique = "T1590.005 - Network Info Gathering, T1189 - Drive-by Compromise";
                            capture.ThreatDetected = "AN1476 - Unauthorized Network Connection";
                        }
                        else
                        {
                            capture.MitreTactic = "Credential Access";
                            capture.MitreTechnique = "T1040 - Network Sniffing";
                            capture.ThreatDetected = "AN1476 - Unsecured Wi-Fi Connection";
                        }
                    }
                    
                    capture.Security = $"{authType} ({securityStatus})";
                }
                else if (trimmedLine.StartsWith("Name", StringComparison.OrdinalIgnoreCase) && trimmedLine.Contains(":"))
                    capture.Interface = trimmedLine.Split(':', 2)[1].Trim();
                else if (trimmedLine.StartsWith("Connection time", StringComparison.OrdinalIgnoreCase) && trimmedLine.Contains(":"))
                {
                    var timeStr = trimmedLine.Split(':', 2)[1].Trim();
                    if (DateTime.TryParse(timeStr, out var connectionTime))
                        capture.ConnectionTime = connectionTime;
                }
            }

            // Set connection time to current time if not found in interface data
            if (!capture.ConnectionTime.HasValue)
            {
                capture.ConnectionTime = DateTime.Now;
            }

            return capture;
        }



        private static async Task<bool> CheckVPNStatus()
        {
            try
            {
                // Check for VPN adapters in network interfaces
                var rasOutput = await RunCommandAsync("rasdial", "");
                if (rasOutput.Contains("Connected", StringComparison.OrdinalIgnoreCase))
                    return true;

                // Check for common VPN adapter names
                var ipConfigOutput = await RunCommandAsync("ipconfig", "/all");
                var vpnKeywords = new[] { "vpn", "tap", "tun", "openvpn", "wireguard", "nordvpn", "expressvpn" };
                
                return vpnKeywords.Any(keyword => 
                    ipConfigOutput.Contains(keyword, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private static bool HasWPA2OrWPA3(string authType)
        {
            var lowerAuth = authType.ToLower();
            return lowerAuth.Contains("wpa2") || lowerAuth.Contains("wpa3");
        }

        private static bool IsAuthorizedNetwork(string? ssid)
        {
            if (string.IsNullOrWhiteSpace(ssid)) return false;
            var authorizedSSIDs = GetAuthorizedSSIDs();
            return authorizedSSIDs.Contains(ssid, StringComparer.OrdinalIgnoreCase);
        }
        
        private static bool IsPublicWiFi(string? ssid)
        {
            if (string.IsNullOrWhiteSpace(ssid)) return false;
            
            var lowerSSID = ssid.ToLower();
            return lowerSSID.Contains("free") || lowerSSID.Contains("public") || 
                   lowerSSID.Contains("guest") || lowerSSID.Contains("open") ||
                   lowerSSID.Contains("wifi") || lowerSSID.Contains("hotspot") ||
                   lowerSSID.Contains("starbucks") || lowerSSID.Contains("mcdonalds") ||
                   lowerSSID.Contains("airport") || lowerSSID.Contains("hotel") ||
                   lowerSSID.Contains("cafe") || lowerSSID.Contains("restaurant") ||
                   lowerSSID.Contains("mall") || lowerSSID.Contains("library");
        }
        
        private static HashSet<string> GetAuthorizedSSIDs()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "authorized-ssids.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    var config = JsonSerializer.Deserialize<AuthorizedSSIDConfig>(json);
                    return new HashSet<string>(config?.AuthorizedSSIDs ?? [], StringComparer.OrdinalIgnoreCase);
                }
            }
            catch { }
            
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CORPORATE-WIFI" };
        }
        
        private class AuthorizedSSIDConfig
        {
            public string[] AuthorizedSSIDs { get; set; } = [];
        }

        private static bool IsSecureConnection(string authType)
        {
            return authType.ToLower() switch
            {
                "open" => false,
                "none" => false,
                var type when type.Contains("wep") => false, // WEP is considered insecure
                var type when type.Contains("wpa") => true,
                var type when type.Contains("wpa2") => true,
                var type when type.Contains("wpa3") => true,
                _ => true // Default to secure for unknown types
            };
        }

        private static string ConvertRadioTypeToFrequency(string radioType)
        {
            return radioType.ToLower() switch
            {
                var type when type.Contains("802.11a") => "5 GHz",
                var type when type.Contains("802.11ac") => "5 GHz",
                var type when type.Contains("802.11ax") => "2.4/5 GHz",
                var type when type.Contains("802.11n") => "2.4/5 GHz",
                var type when type.Contains("802.11g") => "2.4 GHz",
                var type when type.Contains("802.11b") => "2.4 GHz",
                _ => radioType
            };
        }

        private static string? ExtractBSSIDFromNetworks(string networksOutput, string targetSSID)
        {
            if (string.IsNullOrWhiteSpace(networksOutput) || string.IsNullOrWhiteSpace(targetSSID)) return null;

            var lines = networksOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            bool foundTargetSSID = false;

            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                
                if (trimmedLine.StartsWith("SSID", StringComparison.OrdinalIgnoreCase))
                {
                    var ssid = trimmedLine.Split(':', 2)[1].Trim();
                    foundTargetSSID = ssid.Equals(targetSSID, StringComparison.OrdinalIgnoreCase);
                }
                else if (foundTargetSSID && trimmedLine.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                {
                    var bssid = trimmedLine.Split(':', 2)[1].Trim();
                    if (!string.IsNullOrWhiteSpace(bssid))
                        return bssid;
                }
            }

            return null;
        }

        private static string? ExtractIPAddress(string ipConfigOutput, string? interfaceName)
        {
            if (string.IsNullOrWhiteSpace(ipConfigOutput) || string.IsNullOrWhiteSpace(interfaceName))
                return null;

            var lines = ipConfigOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            bool foundInterface = false;

            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                
                if (trimmedLine.Contains(interfaceName, StringComparison.OrdinalIgnoreCase))
                {
                    foundInterface = true;
                    continue;
                }

                if (foundInterface)
                {
                    if (trimmedLine.StartsWith("IPv4 Address", StringComparison.OrdinalIgnoreCase) ||
                        trimmedLine.StartsWith("IP Address", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = trimmedLine.Split(':', 2);
                        if (parts.Length > 1)
                            return parts[1].Trim().Replace("(Preferred)", "").Trim();
                    }
                    else if (trimmedLine.Length == 0 || trimmedLine.Contains("adapter", StringComparison.OrdinalIgnoreCase))
                    {
                        foundInterface = false;
                    }
                }
            }

            return null;
        }
    }
}