using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace be_guardianprotocol.Windows
{
    public class WindowsGeolocationSecurityCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private readonly GeolocationConfig _config;
        private readonly HttpClient _httpClient;
        private static Dictionary<string, UserLocationHistory> _userLocations = new();

        public WindowsGeolocationSecurityCollector()
        {
            _logger = new NetworkConnectionLogger();
            _config = LoadConfig();
            _httpClient = new HttpClient();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var currentIP = await GetPublicIPAsync();
                var geoLocation = await GetGeolocationAsync(currentIP);
                var authEvents = await GetRemoteAuthEventsAsync();
                var riskAnalysis = AnalyzeGeographicRisk(geoLocation, authEvents);

                if (riskAnalysis.IsHighRisk || riskAnalysis.ImpossibleTravel || authEvents.Any())
                {
                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.GEOLOCATION_SECURITY,
                        IsConnected = false,
                        Timestamp = DateTime.Now,
                        Security = BuildSecurityMessage(geoLocation, riskAnalysis, authEvents),
                        HipaaViolation = riskAnalysis.IsHighRisk,
                        ComplianceRule = "HIPAA 164.312(a)(1) & 164.308(a)(1)",
                        MitreTactic = "Initial Access, Defense Evasion, Command & Control",
                        MitreTechnique = "T1078 - Valid Accounts, T1090 - Proxy, T1219 - Remote Access Software",
                        ThreatDetected = "AN0119 - Geographic Access Anomaly",
                        VpnConnectionCount = riskAnalysis.RiskScore
                    };

                    await _logger.LogConnectionAsync(capture);
                    results.Add(capture);
                }
            }
            catch (Exception ex)
            {
                var errorCapture = new SignalCapture
                {
                    Type = SignalTypes.GEOLOCATION_SECURITY,
                    IsConnected = false,
                    Timestamp = DateTime.Now,
                    ErrorMessage = ex.Message
                };
                results.Add(errorCapture);
            }

            return results;
        }

        private async Task<string> GetPublicIPAsync()
        {
            try
            {
                var response = await _httpClient.GetStringAsync("https://api.ipify.org");
                return response.Trim();
            }
            catch
            {
                return "";
            }
        }

        private async Task<GeolocationInfo> GetGeolocationAsync(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return new GeolocationInfo();

            try
            {
                var response = await _httpClient.GetStringAsync($"http://ip-api.com/json/{ipAddress}");
                var geoData = JsonSerializer.Deserialize<IpApiResponse>(response);
                
                return new GeolocationInfo
                {
                    IPAddress = ipAddress,
                    Country = geoData?.country ?? "",
                    CountryCode = geoData?.countryCode ?? "",
                    Region = geoData?.regionName ?? "",
                    City = geoData?.city ?? "",
                    Latitude = geoData?.lat ?? 0,
                    Longitude = geoData?.lon ?? 0,
                    ISP = geoData?.isp ?? "",
                    Timezone = geoData?.timezone ?? ""
                };
            }
            catch
            {
                return new GeolocationInfo { IPAddress = ipAddress };
            }
        }

        private async Task<List<RemoteAuthEvent>> GetRemoteAuthEventsAsync()
        {
            var events = new List<RemoteAuthEvent>();

            try
            {
                var eventLogQuery = await RunCommandAsync("wevtutil", 
                    "qe Security /c:50 /f:text /q:\"*[System[EventID=4624 or EventID=4625] and EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]\"");

                if (!string.IsNullOrEmpty(eventLogQuery))
                {
                    events.AddRange(ParseRemoteAuthEvents(eventLogQuery));
                }
            }
            catch { /* Silent fail */ }

            return events;
        }

        private List<RemoteAuthEvent> ParseRemoteAuthEvents(string eventLogData)
        {
            var events = new List<RemoteAuthEvent>();
            var eventBlocks = eventLogData.Split(new[] { "Event[" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var block in eventBlocks)
            {
                try
                {
                    var eventIdMatch = Regex.Match(block, @"EventID:\s*(\d+)");
                    var userMatch = Regex.Match(block, @"Account Name:\s*([^\r\n]+)");
                    var sourceIpMatch = Regex.Match(block, @"Source Network Address:\s*([^\r\n]+)");
                    var timeMatch = Regex.Match(block, @"Date:\s*([^\r\n]+)");

                    if (eventIdMatch.Success && userMatch.Success && sourceIpMatch.Success)
                    {
                        var sourceIP = sourceIpMatch.Groups[1].Value.Trim();
                        if (!IsLocalIP(sourceIP))
                        {
                            events.Add(new RemoteAuthEvent
                            {
                                EventId = int.Parse(eventIdMatch.Groups[1].Value),
                                Username = userMatch.Groups[1].Value.Trim(),
                                SourceIP = sourceIP,
                                Timestamp = DateTime.Now,
                                IsSuccess = int.Parse(eventIdMatch.Groups[1].Value) == 4624
                            });
                        }
                    }
                }
                catch { /* Skip malformed events */ }
            }

            return events;
        }

        private GeographicRiskAnalysis AnalyzeGeographicRisk(GeolocationInfo currentLocation, List<RemoteAuthEvent> authEvents)
        {
            var analysis = new GeographicRiskAnalysis();
            var username = Environment.UserName;

            // Check if current location is high-risk
            analysis.IsHighRisk = IsHighRiskCountry(currentLocation.CountryCode) || 
                                 IsAnonymizingService(currentLocation.ISP);

            // Calculate risk score
            analysis.RiskScore = CalculateRiskScore(currentLocation);

            // Check for impossible travel
            if (_userLocations.ContainsKey(username))
            {
                var lastLocation = _userLocations[username].LastLocation;
                var timeDiff = DateTime.Now - _userLocations[username].LastAccessTime;
                var distance = CalculateDistance(lastLocation.Latitude, lastLocation.Longitude,
                                               currentLocation.Latitude, currentLocation.Longitude);
                
                var maxPossibleSpeed = distance / Math.Max(timeDiff.TotalHours, 0.1);
                if (maxPossibleSpeed > _config.MaxTravelSpeedKmh)
                {
                    analysis.ImpossibleTravel = true;
                    analysis.TravelSpeed = maxPossibleSpeed;
                }
            }

            // Update user location history
            if (!_userLocations.ContainsKey(username))
                _userLocations[username] = new UserLocationHistory();
            
            _userLocations[username].LastLocation = currentLocation;
            _userLocations[username].LastAccessTime = DateTime.Now;
            _userLocations[username].AccessCount++;

            // Analyze remote auth events
            foreach (var authEvent in authEvents)
            {
                if (IsHighRiskCountry(GetCountryFromIP(authEvent.SourceIP)))
                {
                    analysis.HighRiskAuthAttempts++;
                }
            }

            return analysis;
        }

        private bool IsHighRiskCountry(string countryCode)
        {
            return _config.HighRiskCountries.Contains(countryCode.ToUpper());
        }

        private bool IsAnonymizingService(string isp)
        {
            var anonymizers = new[] { "tor", "vpn", "proxy", "anonymous", "hide", "tunnel" };
            return anonymizers.Any(term => isp.ToLower().Contains(term));
        }

        private int CalculateRiskScore(GeolocationInfo location)
        {
            int score = 0;
            
            if (IsHighRiskCountry(location.CountryCode)) score += 50;
            if (IsAnonymizingService(location.ISP)) score += 30;
            if (!_config.ApprovedCountries.Contains(location.CountryCode.ToUpper())) score += 20;
            
            return Math.Min(score, 100);
        }

        private double CalculateDistance(double lat1, double lon1, double lat2, double lon2)
        {
            const double R = 6371; // Earth's radius in km
            var dLat = (lat2 - lat1) * Math.PI / 180;
            var dLon = (lon2 - lon1) * Math.PI / 180;
            var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                    Math.Cos(lat1 * Math.PI / 180) * Math.Cos(lat2 * Math.PI / 180) *
                    Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
            var c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
            return R * c;
        }

        private bool IsLocalIP(string ip)
        {
            var localRanges = new[] { "192.168.", "10.", "172.16.", "127.", "169.254." };
            return localRanges.Any(range => ip.StartsWith(range));
        }

        private string GetCountryFromIP(string ip)
        {
            // Simplified - would normally do IP lookup
            return "";
        }

        private string BuildSecurityMessage(GeolocationInfo location, GeographicRiskAnalysis risk, List<RemoteAuthEvent> authEvents)
        {
            var messages = new List<string>();

            if (risk.IsHighRisk)
            {
                messages.Add($"HIGH RISK LOCATION: {location.Country} ({location.CountryCode})");
            }

            if (risk.ImpossibleTravel)
            {
                messages.Add($"IMPOSSIBLE TRAVEL: {risk.TravelSpeed:F0} km/h");
            }

            if (risk.HighRiskAuthAttempts > 0)
            {
                messages.Add($"HIGH RISK AUTH: {risk.HighRiskAuthAttempts} attempts");
            }

            if (IsAnonymizingService(location.ISP))
            {
                messages.Add($"ANONYMIZING SERVICE: {location.ISP}");
            }

            if (authEvents.Any(e => !e.IsSuccess))
            {
                messages.Add($"FAILED REMOTE AUTH: {authEvents.Count(e => !e.IsSuccess)} attempts");
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

        private GeolocationConfig LoadConfig()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "geolocation-config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<GeolocationConfig>(json) ?? new GeolocationConfig();
                }
            }
            catch { /* Silent fail */ }

            return new GeolocationConfig();
        }
    }

    public class GeolocationConfig
    {
        public List<string> HighRiskCountries { get; set; } = new()
        {
            "CN", "RU", "KP", "IR", "SY", "AF", "IQ", "LY", "SO", "SD", "YE", "MM"
        };

        public List<string> ApprovedCountries { get; set; } = new()
        {
            "US", "CA", "GB", "AU", "DE", "FR", "JP", "NL", "SE", "NO", "DK", "FI"
        };

        public double MaxTravelSpeedKmh { get; set; } = 1000; // Max realistic travel speed
    }

    public class GeolocationInfo
    {
        public string IPAddress { get; set; } = "";
        public string Country { get; set; } = "";
        public string CountryCode { get; set; } = "";
        public string Region { get; set; } = "";
        public string City { get; set; } = "";
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public string ISP { get; set; } = "";
        public string Timezone { get; set; } = "";
    }

    public class RemoteAuthEvent
    {
        public int EventId { get; set; }
        public string Username { get; set; } = "";
        public string SourceIP { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public bool IsSuccess { get; set; }
    }

    public class GeographicRiskAnalysis
    {
        public bool IsHighRisk { get; set; }
        public bool ImpossibleTravel { get; set; }
        public double TravelSpeed { get; set; }
        public int RiskScore { get; set; }
        public int HighRiskAuthAttempts { get; set; }
    }

    public class UserLocationHistory
    {
        public GeolocationInfo LastLocation { get; set; } = new();
        public DateTime LastAccessTime { get; set; }
        public int AccessCount { get; set; }
    }

    public class IpApiResponse
    {
        public string country { get; set; } = "";
        public string countryCode { get; set; } = "";
        public string regionName { get; set; } = "";
        public string city { get; set; } = "";
        public double lat { get; set; }
        public double lon { get; set; }
        public string isp { get; set; } = "";
        public string timezone { get; set; } = "";
    }
}