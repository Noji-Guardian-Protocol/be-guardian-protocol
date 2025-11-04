using Azure.Messaging.ServiceBus;
using be_guardianprotocol.Core.Models;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace be_guardianprotocol.Core.Services
{
    public class FeatureExtractionEngine
    {
        private readonly string _logFilePath;
        private readonly string _csvOutputPath;
        private readonly ServiceBusClient? _serviceBusClient;
        private ServiceBusSender? _sender;
        private ITenantConfigurationService? _tenantService;

        public FeatureExtractionEngine(string? serviceBusConnectionString = null, ITenantConfigurationService? tenantService = null)
        {
            _logFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                "GuardianProtocol", "signal_events.json");
            _csvOutputPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                "GuardianProtocol", "behavioral_features.csv");
            
            _tenantService = tenantService;
            
            try
            {
                _serviceBusClient = new ServiceBusClient(serviceBusConnectionString);
            }
            catch { /* Service Bus initialization failed */ }
        }

        public void UpdateTenantService(ITenantConfigurationService tenantService)
        {
            _tenantService = tenantService;
        }

        public async Task<BehavioralFeatures> ExtractFeaturesAsync()
        {
            var signals = await LoadSignalEventsAsync();
            var features = ProcessSignals(signals);
            await WriteCsvAsync(features);
            await SendToServiceBusAsync(features);
            return features;
        }

        private async Task<List<SignalEventLog>> LoadSignalEventsAsync()
        {
            var signals = new List<SignalEventLog>();
            
            if (!File.Exists(_logFilePath)) return signals;

            var lines = await File.ReadAllLinesAsync(_logFilePath);
            foreach (var line in lines)
            {
                try
                {
                    var signal = JsonSerializer.Deserialize<SignalEventLog>(line);
                    if (signal != null) signals.Add(signal);
                }
                catch { /* Skip invalid lines */ }
            }

            return signals;
        }

        private BehavioralFeatures ProcessSignals(List<SignalEventLog> signals)
        {
            var signalType = signals.FirstOrDefault()?.SignalType ?? "Unknown";
            
            var features = new BehavioralFeatures { 
                Timestamp = DateTimeOffset.Now.ToUnixTimeMilliseconds(),
                SignalType = signalType
            };

            switch (signalType)
            {
                case "Keyboard": ProcessKeyboardFeatures(features, signals); break;
                case "Mouse": ProcessMouseFeatures(features, signals); break;
                case "Process": ProcessApplicationFeatures(features, signals); break;
                case "Network": ProcessNetworkFeatures(features, signals); break;
                case "TextAnalysis": ProcessTextFeatures(features, signals); break;
                case "VPN": ProcessVpnFeatures(features, signals); break;
                case "Encryption": ProcessEncryptionFeatures(features, signals); break;
                case "Wifi": ProcessWifiFeatures(features, signals); break;
                case "USB": ProcessUSBExfiltrationFeatures(features, signals); break;
                case "VPN_BYPASS": ProcessVpnBypassFeatures(features, signals); break;
                case "PASSWORD_SECURITY": ProcessPasswordSecurityFeatures(features, signals); break;
                case "GEOLOCATION_SECURITY": ProcessGeolocationSecurityFeatures(features, signals); break;
                case "HOTSPOT_SECURITY": ProcessHotspotSecurityFeatures(features, signals); break;
                case "SCREEN_LOCK_SECURITY": ProcessScreenLockSecurityFeatures(features, signals); break;
                case "SESSION_TIMEOUT_SECURITY": ProcessSessionTimeoutFeatures(features, signals); break;
                case "PASSWORD_LENGTH_SECURITY": ProcessPasswordLengthFeatures(features, signals); break;
                case "MFA_SECURITY": ProcessMfaSecurityFeatures(features, signals); break;
                case "PASSWORD_EXPIRATION": ProcessPasswordExpirationFeatures(features, signals); break;
                case "UNAUTHORIZED_SOFTWARE": ProcessUnauthorizedSoftwareFeatures(features, signals); break;
                case "AUTOMATED_UPDATE": ProcessAutomatedUpdateFeatures(features, signals); break;
                case "UNAUTHORIZED_DATA_SHARING": ProcessUnauthorizedDataSharingFeatures(features, signals); break;
                case "UNAUTHORIZED_CLOUD_STORAGE": ProcessUnauthorizedCloudStorageFeatures(features, signals); break;
                case "Bluetooth": ProcessBluetoothFeatures(features, signals); break;
                case "SYSTEM_INFO": ProcessSystemInfoFeatures(features, signals); break;
            }

            return features;
        }

        private void ProcessKeyboardFeatures(BehavioralFeatures features, List<SignalEventLog> keyboardSignals)
        {
            features.KeystrokeCounter = keyboardSignals.Count;
            features.EraseKeysCounter = keyboardSignals.Count(k => k.KeyPressed == "Backspace" || k.KeyPressed == "Delete");
            features.EraseKeysPercentage = features.KeystrokeCounter > 0 ? 
                (double)features.EraseKeysCounter / features.KeystrokeCounter * 100 : 0;

            var intervals = new List<double>();
            var words = new List<string>();
            var currentWord = "";
            
            for (int i = 1; i < keyboardSignals.Count; i++)
            {
                var interval = (keyboardSignals[i].Timestamp - keyboardSignals[i-1].Timestamp).TotalMilliseconds;
                intervals.Add(interval);
            }

            features.PressPressAverageInterval = intervals.Any() ? intervals.Average() : 0;
            features.PressPressStddevInterval = intervals.Any() ? CalculateStdDev(intervals) : 0;
            features.PressReleaseAverageInterval = keyboardSignals.Average(k => k.InterKeyLatency ?? 0);
            features.PressReleaseStddevInterval = CalculateStdDev(keyboardSignals.Select(k => k.InterKeyLatency ?? 0));

            // Process individual keystrokes and build words
            foreach (var signal in keyboardSignals)
            {
                if (!string.IsNullOrEmpty(signal.KeyPressed))
                {
                    var key = NormalizeKey(signal.KeyPressed);
                    features.KeystrokeCounts[key] = features.KeystrokeCounts.GetValueOrDefault(key, 0) + 1;
                    
                    var latency = signal.InterKeyLatency ?? 0;
                    if (latency > 0)
                    {
                        var currentAvg = features.PressReleaseAverages.GetValueOrDefault(key, 0);
                        var count = features.KeystrokeCounts[key];
                        features.PressReleaseAverages[key] = (currentAvg * (count - 1) + latency) / count;
                    }
                    
                    // Build words for analysis
                    if (key == "space" || key == "inter")
                    {
                        if (!string.IsNullOrEmpty(currentWord))
                        {
                            words.Add(currentWord);
                            currentWord = "";
                        }
                    }
                    else if (char.IsLetter(key.FirstOrDefault()))
                    {
                        currentWord += key;
                    }
                }
            }
            
            if (!string.IsNullOrEmpty(currentWord)) words.Add(currentWord);
            
            // Process word statistics
            ProcessWordStatistics(features, words);
            
            // Process digraphs
            ProcessDigraphs(features, keyboardSignals);
        }

        private void ProcessMouseFeatures(BehavioralFeatures features, List<SignalEventLog> mouseSignals)
        {
            var clickSignals = mouseSignals.Where(m => !string.IsNullOrEmpty(m.Button)).ToList();
            var movementSignals = mouseSignals.Where(m => m.PositionX.HasValue && m.PositionY.HasValue).ToList();
            
            // Process click speeds by button type
            var buttonTypes = new[] { "Left", "Right", "Middle", "X1" };
            for (int i = 0; i < 4; i++)
            {
                var buttonClicks = clickSignals.Where(c => c.Button == buttonTypes[i]).ToList();
                if (buttonClicks.Count > 1)
                {
                    var intervals = new List<double>();
                    for (int j = 1; j < buttonClicks.Count; j++)
                    {
                        intervals.Add((buttonClicks[j].Timestamp - buttonClicks[j-1].Timestamp).TotalMilliseconds);
                    }
                    features.ClickSpeedAverage[i] = intervals.Average();
                    features.ClickSpeedStddev[i] = CalculateStdDev(intervals);
                }
            }

            // Mouse action counters (clicks, moves, scrolls, etc.)
            features.MouseActionCounter[0] = clickSignals.Count(c => c.Button == "Left");
            features.MouseActionCounter[1] = clickSignals.Count(c => c.Button == "Right");
            features.MouseActionCounter[2] = clickSignals.Count(c => c.Button == "Middle");
            features.MouseActionCounter[3] = 0; // Scroll events not available in SignalEventLog
            features.MouseActionCounter[4] = movementSignals.Count;
            features.MouseActionCounter[5] = clickSignals.Count(c => c.ClickType == "Double");
            features.MouseActionCounter[6] = clickSignals.Count(c => c.ClickType == "Drag");

            // Position histogram (9 screen regions)
            foreach (var signal in movementSignals)
            {
                var region = CalculateScreenRegion(signal.PositionX ?? 0, signal.PositionY ?? 0);
                if (region >= 0 && region < 9)
                    features.MousePositionHistogram[region]++;
            }
            
            // Movement analysis
            ProcessMouseMovements(features, movementSignals);
        }

        private void ProcessApplicationFeatures(BehavioralFeatures features, List<SignalEventLog> processSignals)
        {
            if (!processSignals.Any()) return;
            
            var latest = processSignals.LastOrDefault();
            if (latest != null)
            {
                features.ActiveAppsAverage = latest.ActiveProcessCount ?? 0;
                features.CurrentApp = latest.CurrentApp ?? "";
                features.PenultimateApp = latest.PreviousApp ?? "";
                features.ChangesBetweenApps = latest.AppSwitchCount ?? 0;
                features.CurrentAppForegroundTime = latest.AppForegroundTime ?? 0;
            }
            
            // Calculate averages and standard deviations
            var cpuValues = processSignals.Where(p => p.SystemCpuUsage.HasValue).Select(p => p.SystemCpuUsage.Value).ToList();
            var memValues = processSignals.Where(p => p.SystemMemoryUsage.HasValue).Select(p => p.SystemMemoryUsage.Value).ToList();
            var appCpuValues = processSignals.Where(p => p.CurrentAppCpuUsage.HasValue).Select(p => p.CurrentAppCpuUsage.Value).ToList();
            var appMemValues = processSignals.Where(p => p.CurrentAppMemoryUsage.HasValue).Select(p => (double)p.CurrentAppMemoryUsage.Value).ToList();
            var processCountValues = processSignals.Where(p => p.ActiveProcessCount.HasValue).Select(p => (double)p.ActiveProcessCount.Value).ToList();
            
            features.SystemAverageCpu = cpuValues.Any() ? cpuValues.Average() : 0;
            features.SystemStddevCpu = cpuValues.Any() ? CalculateStdDev(cpuValues) : 0;
            features.SystemAverageMem = memValues.Any() ? memValues.Average() : 0;
            features.SystemStddevMem = memValues.Any() ? CalculateStdDev(memValues) : 0;
            features.CurrentAppAverageCpu = appCpuValues.Any() ? appCpuValues.Average() : 0;
            features.CurrentAppStddevCpu = appCpuValues.Any() ? CalculateStdDev(appCpuValues) : 0;
            features.CurrentAppAverageMem = appMemValues.Any() ? appMemValues.Average() : 0;
            features.CurrentAppStddevMem = appMemValues.Any() ? CalculateStdDev(appMemValues) : 0;
            features.CurrentAppAverageProcesses = processCountValues.Any() ? processCountValues.Average() : 0;
            features.CurrentAppStddevProcesses = processCountValues.Any() ? CalculateStdDev(processCountValues) : 0;
        }

        private void ProcessNetworkFeatures(BehavioralFeatures features, List<SignalEventLog> networkSignals)
        {
            var latest = networkSignals.LastOrDefault();
            if (latest != null)
            {
                features.ReceivedBytes = latest.BytesReceived ?? 0;
                features.SentBytes = latest.BytesSent ?? 0;
            }
        }

        private void ProcessTextFeatures(BehavioralFeatures features, List<SignalEventLog> textSignals)
        {
            var latest = textSignals.LastOrDefault();
            if (latest != null)
            {
                features.WordCounter = latest.WordCount ?? 0;
                features.WordAverageLength = latest.AverageWordLength ?? 0;
            }
        }
        
        private void ProcessWordStatistics(BehavioralFeatures features, List<string> words)
        {
            if (!words.Any()) return;
            
            features.WordCounter = words.Count;
            var lengths = words.Select(w => (double)w.Length).ToList();
            features.WordAverageLength = lengths.Average();
            features.WordStddevLength = CalculateStdDev(lengths);
            
            // Word length distribution
            foreach (var word in words)
            {
                var len = Math.Min(word.Length, 11);
                switch (len)
                {
                    case 1: features.WordLength1++; break;
                    case 2: features.WordLength2++; break;
                    case 3: features.WordLength3++; break;
                    case 4: features.WordLength4++; break;
                    case 5: features.WordLength5++; break;
                    case 6: features.WordLength6++; break;
                    case 7: features.WordLength7++; break;
                    case 8: features.WordLength8++; break;
                    case 9: features.WordLength9++; break;
                    case 10: features.WordLength10++; break;
                    case 11: features.WordLength11++; break;
                }
            }
        }
        
        private void ProcessDigraphs(BehavioralFeatures features, List<SignalEventLog> keyboardSignals)
        {
            for (int i = 1; i < keyboardSignals.Count; i++)
            {
                var key1 = NormalizeKey(keyboardSignals[i-1].KeyPressed ?? "");
                var key2 = NormalizeKey(keyboardSignals[i].KeyPressed ?? "");
                
                if (!string.IsNullOrEmpty(key1) && !string.IsNullOrEmpty(key2))
                {
                    var digraph = $"{key1}{key2}";
                    features.DigraphCounters[digraph] = features.DigraphCounters.GetValueOrDefault(digraph, 0) + 1;
                    
                    var timeDiff = (keyboardSignals[i].Timestamp - keyboardSignals[i-1].Timestamp).TotalMilliseconds;
                    var currentAvg = features.DigraphAverageTimes.GetValueOrDefault(digraph, 0);
                    var count = features.DigraphCounters[digraph];
                    features.DigraphAverageTimes[digraph] = (currentAvg * (count - 1) + timeDiff) / count;
                }
            }
        }
        
        private void ProcessMouseMovements(BehavioralFeatures features, List<SignalEventLog> movementSignals)
        {
            if (movementSignals.Count < 2) return;
            
            var movements = new List<(double distance, double duration, int direction)>();
            
            for (int i = 1; i < movementSignals.Count; i++)
            {
                var prev = movementSignals[i-1];
                var curr = movementSignals[i];
                
                if (prev.PositionX.HasValue && prev.PositionY.HasValue && 
                    curr.PositionX.HasValue && curr.PositionY.HasValue)
                {
                    var dx = curr.PositionX.Value - prev.PositionX.Value;
                    var dy = curr.PositionY.Value - prev.PositionY.Value;
                    var distance = Math.Sqrt(dx * dx + dy * dy);
                    var duration = (curr.Timestamp - prev.Timestamp).TotalMilliseconds;
                    var direction = CalculateDirection(dx, dy);
                    
                    movements.Add((distance, duration, direction));
                }
            }
            
            if (movements.Any())
            {
                features.MouseAverageMovementDuration = movements.Average(m => m.duration);
                features.MouseAverageMovementSpeed = movements.Average(m => m.distance / Math.Max(m.duration, 1));
                
                // Direction histogram (8 directions)
                foreach (var movement in movements)
                {
                    if (movement.direction >= 0 && movement.direction < 8)
                        features.MouseMovementDirectionHistogram[movement.direction]++;
                }
                
                // Length histogram (3 categories: short, medium, long)
                foreach (var movement in movements)
                {
                    var category = movement.distance < 50 ? 0 : movement.distance < 200 ? 1 : 2;
                    features.MouseMovementLengthHistogram[category]++;
                }
                
                // Speed by direction
                for (int dir = 0; dir < 8; dir++)
                {
                    var dirMovements = movements.Where(m => m.direction == dir).ToList();
                    if (dirMovements.Any())
                    {
                        features.MouseAverageMovementSpeedDirection[dir] = 
                            dirMovements.Average(m => m.distance / Math.Max(m.duration, 1));
                    }
                }
            }
        }
        
        private string NormalizeKey(string key)
        {
            if (string.IsNullOrEmpty(key)) return "";
            
            return key.ToLower() switch
            {
                "backspace" => "backspace",
                "delete" => "delete",
                "enter" => "inter",
                "return" => "inter",
                "tab" => "tab",
                "escape" => "esc",
                "lwin" => "leftwindows",
                "rwin" => "rightwindows",
                "lshift" => "shift",
                "rshift" => "rightshift",
                "lctrl" => "leftctrl",
                "rctrl" => "rightctrl",
                "lalt" => "alt",
                "ralt" => "rightalt",
                " " => "space",
                _ => key.ToLower()
            };
        }
        
        private int CalculateDirection(double dx, double dy)
        {
            if (dx == 0 && dy == 0) return -1;
            
            var angle = Math.Atan2(dy, dx) * 180 / Math.PI;
            if (angle < 0) angle += 360;
            
            return (int)((angle + 22.5) / 45) % 8;
        }

        private void ProcessVpnFeatures(BehavioralFeatures features, List<SignalEventLog> vpnSignals)
        {
            var latest = vpnSignals.LastOrDefault();
            if (latest != null)
            {
                features.VpnConnected = latest.IsConnected ?? false;
                features.CorporateVpnUsed = latest.CorporateVpnDetected ?? false;
                features.UntrustedNetworkDetected = latest.IsUntrustedNetwork ?? false;
                features.HipaaViolationDetected = latest.HipaaViolation ?? false;
                features.VpnConnectionCount = latest.VpnConnectionCount ?? 0;
            }
            else
            {
                features.VpnConnected = false;
                features.CorporateVpnUsed = false;
                features.UntrustedNetworkDetected = false;
                features.HipaaViolationDetected = false;
                features.VpnConnectionCount = 0;
            }
        }

        private void ProcessEncryptionFeatures(BehavioralFeatures features, List<SignalEventLog> encryptionSignals)
        {
            var latest = encryptionSignals.LastOrDefault();
            if (latest != null)
            {
                features.EncryptionEnabled = latest.EncryptionEnabled ?? false;
                features.EncryptionMethod = latest.EncryptionMethod ?? "";
                features.TmpEnabled = latest.TmpEnabled ?? false;
                features.EncryptedVolumeCount = latest.EncryptedVolumeCount ?? 0;
                features.UnencryptedVolumeCount = latest.UnencryptedVolumeCount ?? 0;
            }
        }
        
        private void ProcessWifiFeatures(BehavioralFeatures features, List<SignalEventLog> wifiSignals)
        {
            var latest = wifiSignals.LastOrDefault();
            if (latest != null)
            {
                features.WifiConnected = latest.IsConnected ?? false;
                features.WifiSecurityType = latest.Security ?? "";
                features.UnauthorizedNetworkDetected = latest.HipaaViolation ?? false;
                // Get signal strength from Security field if available
                if (latest.Security?.Contains("%") == true)
                {
                    var strengthMatch = System.Text.RegularExpressions.Regex.Match(latest.Security, @"(\d+)%");
                    if (strengthMatch.Success && double.TryParse(strengthMatch.Groups[1].Value, out var strength))
                        features.WifiSignalStrength = strength;
                }
                else
                {
                    features.WifiSignalStrength = 0;
                }
            }
        }
        
        private void ProcessApplicationSecurityFeatures(BehavioralFeatures features, List<SignalEventLog> appSecuritySignals)
        {
            features.UnauthorizedAppDetected = appSecuritySignals.Any();
            features.UnauthorizedAppCount = appSecuritySignals.Count;
            
            var torrentApps = appSecuritySignals.Where(s => s.Security?.Contains("TORRENT") == true).ToList();
            features.TorrentActivityDetected = torrentApps.Any();
            features.TorrentAppCount = torrentApps.Count;
            
            var unsignedApps = appSecuritySignals.Where(s => s.Security?.Contains("UNSIGNED") == true).ToList();
            features.UnsignedAppCount = unsignedApps.Count;
            
            var suspiciousLocationApps = appSecuritySignals.Where(s => s.Security?.Contains("SUSPICIOUS LOCATION") == true).ToList();
            features.SuspiciousLocationAppCount = suspiciousLocationApps.Count;
        }
        
        private void ProcessEndpointProtectionFeatures(BehavioralFeatures features, List<SignalEventLog> endpointSignals)
        {
            features.EndpointProtectionDisabled = endpointSignals.Any(s => s.IsConnected == false);
            features.DisabledSecurityServicesCount = endpointSignals.Count(s => s.IsConnected == false);
            
            var defenderDisabled = endpointSignals.Any(s => s.ProcessName?.Contains("Defender") == true && s.IsConnected == false);
            features.WindowsDefenderDisabled = defenderDisabled;
            
            var criticalServicesDown = endpointSignals.Where(s => 
                (s.ProcessName?.Contains("MsMpSvc") == true || s.ProcessName?.Contains("WinDefend") == true) && 
                s.IsConnected == false).ToList();
            features.CriticalSecurityServicesDown = criticalServicesDown.Count;
        }
        
        private void ProcessUSBExfiltrationFeatures(BehavioralFeatures features, List<SignalEventLog> usbSignals)
        {
            features.SensitiveDataToUSB = usbSignals.Any(s => s.Security?.Contains("SENSITIVE DATA") == true);
            features.UnauthorizedUSBDetected = usbSignals.Any(s => s.Security?.Contains("UNAUTHORIZED") == true);
            features.USBDataTransferCount = usbSignals.Count(s => s.Security?.Contains("Transfer") == true);
            
            var sensitiveTransfers = usbSignals.Where(s => s.Security?.Contains("SENSITIVE DATA") == true).ToList();
            features.SensitiveFileTransferCount = sensitiveTransfers.Count;
            
            var unauthorizedDevices = usbSignals.Where(s => s.Security?.Contains("UNAUTHORIZED") == true).ToList();
            features.UnauthorizedStorageDeviceCount = unauthorizedDevices.Count;
        }
        
        private void ProcessVpnBypassFeatures(BehavioralFeatures features, List<SignalEventLog> vpnBypassSignals)
        {
            features.UnauthorizedVpnDetected = vpnBypassSignals.Any();
            features.UnauthorizedVpnAppCount = vpnBypassSignals.Count(s => s.Security?.Contains("UNAUTHORIZED VPN") == true);
            features.ThirdPartyVpnUsage = vpnBypassSignals.Any(s => s.Security?.Contains("UNAUTHORIZED VPN") == true);
            
            var rejectionSignals = vpnBypassSignals.Where(s => s.Security?.Contains("VPN REJECTION") == true).ToList();
            features.VpnRejectionCount = rejectionSignals.Sum(s => s.VpnConnectionCount ?? 0);
            
            features.VpnAvoidanceDetected = vpnBypassSignals.Any(s => s.Security?.Contains("VPN AVOIDANCE") == true);
        }
        
        private void ProcessPasswordSecurityFeatures(BehavioralFeatures features, List<SignalEventLog> passwordSignals)
        {
            features.WeakPasswordDetected = passwordSignals.Any(s => s.Security?.Contains("WEAK PASSWORD PATTERN") == true);
            features.BruteForceDetected = passwordSignals.Any(s => s.Security?.Contains("BRUTE FORCE") == true);
            features.PasswordPolicyViolation = passwordSignals.Any(s => s.Security?.Contains("POLICY VIOLATION") == true);
            
            var failedLoginSignals = passwordSignals.Where(s => s.Security?.Contains("FAILED LOGINS") == true).ToList();
            features.FailedLoginAttempts = failedLoginSignals.Sum(s => s.VpnConnectionCount ?? 0);
            
            var weakPatternSignals = passwordSignals.Where(s => s.Security?.Contains("WEAK PASSWORD PATTERN") == true).ToList();
            features.WeakPasswordPatternCount = weakPatternSignals.Count;
        }
        
        private void ProcessGeolocationSecurityFeatures(BehavioralFeatures features, List<SignalEventLog> geoSignals)
        {
            features.HighRiskGeolocationDetected = geoSignals.Any(s => s.Security?.Contains("HIGH RISK LOCATION") == true);
            features.ImpossibleTravelDetected = geoSignals.Any(s => s.Security?.Contains("IMPOSSIBLE TRAVEL") == true);
            features.AnonymizingServiceDetected = geoSignals.Any(s => s.Security?.Contains("ANONYMIZING SERVICE") == true);
            
            var riskScoreSignals = geoSignals.Where(s => s.VpnConnectionCount.HasValue).ToList();
            features.GeolocationRiskScore = riskScoreSignals.Any() ? riskScoreSignals.Max(s => s.VpnConnectionCount ?? 0) : 0;
            
            var highRiskAuthSignals = geoSignals.Where(s => s.Security?.Contains("HIGH RISK AUTH") == true).ToList();
            features.HighRiskAuthAttempts = highRiskAuthSignals.Count;
        }
        
        private void ProcessHotspotSecurityFeatures(BehavioralFeatures features, List<SignalEventLog> hotspotSignals)
        {
            features.UnauthorizedHotspotDetected = hotspotSignals.Any(s => s.Security?.Contains("UNAUTHORIZED HOTSPOT") == true);
            features.TetheringDetected = hotspotSignals.Any(s => s.Security?.Contains("TETHERING") == true);
            features.InternetConnectionSharingActive = hotspotSignals.Any(s => s.Security?.Contains("INTERNET CONNECTION SHARING") == true);
            features.NetworkBridgingDetected = hotspotSignals.Any(s => s.Security?.Contains("NETWORK BRIDGING") == true);
            
            var connectedDeviceSignals = hotspotSignals.Where(s => s.VpnConnectionCount.HasValue).ToList();
            features.HotspotConnectedDevices = connectedDeviceSignals.Sum(s => s.VpnConnectionCount ?? 0);
        }
        
        private void ProcessScreenLockSecurityFeatures(BehavioralFeatures features, List<SignalEventLog> screenLockSignals)
        {
            features.ScreenLockPolicyViolation = screenLockSignals.Any();
            features.ScreensaverDisabled = screenLockSignals.Any(s => s.Security?.Contains("SCREENSAVER DISABLED") == true);
            features.ExtendedIdleSession = screenLockSignals.Any(s => s.Security?.Contains("EXTENDED IDLE") == true);
            features.UnlockedTooLong = screenLockSignals.Any(s => s.Security?.Contains("UNLOCKED TOO LONG") == true);
            
            var idleTimeSignals = screenLockSignals.Where(s => s.VpnConnectionCount.HasValue).ToList();
            features.IdleTimeMinutes = idleTimeSignals.Any() ? idleTimeSignals.Max(s => s.VpnConnectionCount ?? 0) : 0;
        }
        
        private void ProcessSessionTimeoutFeatures(BehavioralFeatures features, List<SignalEventLog> sessionTimeoutSignals)
        {
            features.SessionTimeoutViolation = sessionTimeoutSignals.Any(s => s.Security?.Contains("SESSION TIMEOUT VIOLATION") == true);
            features.LongRunningSession = sessionTimeoutSignals.Any(s => s.Security?.Contains("LONG RUNNING SESSION") == true);
            features.IdleApplicationCount = sessionTimeoutSignals.Count(s => s.Security?.Contains("EXTENDED IDLE SESSION") == true);
            
            var idleTimeSignals = sessionTimeoutSignals.Where(s => s.VpnConnectionCount.HasValue).ToList();
            features.MaxSessionIdleMinutes = idleTimeSignals.Any() ? idleTimeSignals.Max(s => s.VpnConnectionCount ?? 0) : 0;
            
            features.RequiresReauthentication = sessionTimeoutSignals.Any(s => s.Security?.Contains("SESSION TIMEOUT VIOLATION") == true || s.Security?.Contains("LONG RUNNING SESSION") == true);
        }
        
        private void ProcessPasswordLengthFeatures(BehavioralFeatures features, List<SignalEventLog> passwordLengthSignals)
        {
            features.PasswordLengthViolation = passwordLengthSignals.Any(s => s.Security?.Contains("POLICY VIOLATION") == true);
            features.GroupPolicyViolation = passwordLengthSignals.Any(s => s.Security?.Contains("GROUP POLICY VIOLATION") == true);
            features.BruteForceOnWeakPasswords = passwordLengthSignals.Any(s => s.Security?.Contains("BRUTE FORCE DETECTED") == true);
            
            var lengthSignals = passwordLengthSignals.Where(s => s.VpnConnectionCount.HasValue).ToList();
            features.CurrentMinPasswordLength = lengthSignals.Any() ? lengthSignals.Max(s => s.VpnConnectionCount ?? 0) : 0;
            
            features.PasswordChangeEvents = passwordLengthSignals.Count(s => s.Security?.Contains("PASSWORD CHANGE DETECTED") == true);
        }
        
        private void ProcessMfaSecurityFeatures(BehavioralFeatures features, List<SignalEventLog> mfaSignals)
        {
            features.SuspiciousMfaRejected = mfaSignals.Any(s => s.Security?.Contains("SUSPICIOUS MFA REJECTED") == true);
            features.MfaFatigueAttackDetected = mfaSignals.Any(s => s.Security?.Contains("MFA FATIGUE ATTACK") == true);
            features.UnauthorizedMfaAppDetected = mfaSignals.Any(s => s.Security?.Contains("UNAUTHORIZED MFA APP") == true);
            
            var rejectionSignals = mfaSignals.Where(s => s.Security?.Contains("SUSPICIOUS MFA REJECTED") == true).ToList();
            features.MfaPromptRejectionCount = rejectionSignals.Sum(s => s.VpnConnectionCount ?? 0);
            
            var offHoursSignals = mfaSignals.Where(s => s.Security?.Contains("OFF HOURS MFA") == true).ToList();
            features.OffHoursMfaAttempts = offHoursSignals.Sum(s => s.VpnConnectionCount ?? 0);
        }
        
        private void ProcessPasswordExpirationFeatures(BehavioralFeatures features, List<SignalEventLog> passwordExpirationSignals)
        {
            features.PasswordExpired = passwordExpirationSignals.Any(s => s.Security?.Contains("PASSWORD EXPIRED") == true);
            features.PasswordExpirationWarning = passwordExpirationSignals.Any(s => s.Security?.Contains("PASSWORD EXPIRATION WARNING") == true);
            features.PasswordChangeOverdue = passwordExpirationSignals.Any(s => s.Security?.Contains("PASSWORD EXPIRED") == true || s.Security?.Contains("PASSWORD EXPIRATION WARNING") == true);
            
            var ageSignals = passwordExpirationSignals.Where(s => s.Security?.Contains("PASSWORD AGE CHECK") == true && s.VpnConnectionCount.HasValue).ToList();
            features.DaysSincePasswordChange = ageSignals.Any() ? ageSignals.Max(s => s.VpnConnectionCount ?? 0) : 0;
            
            features.PasswordExpirationEvents = passwordExpirationSignals.Count(s => s.Security?.Contains("PASSWORD CHANGE") == true || s.Security?.Contains("PASSWORD RESET") == true);
        }
        
        private void ProcessUnauthorizedSoftwareFeatures(BehavioralFeatures features, List<SignalEventLog> softwareSignals)
        {
            features.UnsignedSoftwareInstalled = softwareSignals.Any(s => s.Security?.Contains("UNSIGNED SOFTWARE") == true);
            features.ExternalRepositoryUsed = softwareSignals.Any(s => s.Security?.Contains("EXTERNAL REPOSITORY") == true);
            features.DigitalSignatureViolation = softwareSignals.Any(s => s.Security?.Contains("SIGNATURE VIOLATION") == true);
            features.CorporatePolicyBypass = softwareSignals.Any(s => s.Security?.Contains("POLICY BYPASS") == true);
            
            features.UnapprovedPackageCount = softwareSignals.Count(s => s.Security?.Contains("UNAPPROVED PACKAGE") == true);
            features.UnauthorizedRepositoryCount = softwareSignals.Count(s => s.Security?.Contains("UNAUTHORIZED REPOSITORY") == true);
        }
        
        private void ProcessAutomatedUpdateFeatures(BehavioralFeatures features, List<SignalEventLog> updateSignals)
        {
            features.AutomaticUpdatesDisabled = updateSignals.Any(s => s.Security?.Contains("UPDATES DISABLED") == true);
            features.MissedScheduledUpdates = updateSignals.Any(s => s.Security?.Contains("MISSED SCHEDULED UPDATE") == true);
            features.UpdateServiceFailure = updateSignals.Any(s => s.Security?.Contains("UPDATE SERVICE FAILURE") == true);
            features.OutdatedSoftwareDetected = updateSignals.Any(s => s.Security?.Contains("OUTDATED SOFTWARE") == true);
            
            var daysSignals = updateSignals.Where(s => s.Security?.Contains("DAYS WITHOUT UPDATES") == true && s.VpnConnectionCount.HasValue).ToList();
            features.DaysWithoutSecurityUpdates = daysSignals.Any() ? daysSignals.Max(s => s.VpnConnectionCount ?? 0) : 0;
            
            features.CriticalPatchesPending = updateSignals.Count(s => s.Security?.Contains("CRITICAL PATCH PENDING") == true);
        }
        
        private void ProcessUnauthorizedDataSharingFeatures(BehavioralFeatures features, List<SignalEventLog> dataSharingSignals)
        {
            features.PersonalEmailSharingDetected = dataSharingSignals.Any(s => s.Security?.Contains("PERSONAL EMAIL SHARING") == true);
            features.UnauthorizedCloudUpload = dataSharingSignals.Any(s => s.Security?.Contains("UNAUTHORIZED CLOUD UPLOAD") == true);
            features.PublicFileSharingUsed = dataSharingSignals.Any(s => s.Security?.Contains("PUBLIC FILE SHARING") == true);
            features.DlpPolicyViolation = dataSharingSignals.Any(s => s.Security?.Contains("DLP POLICY VIOLATION") == true);
            
            features.UnapprovedDataTransmissionCount = dataSharingSignals.Count(s => s.Security?.Contains("UNAPPROVED DATA TRANSMISSION") == true);
            features.SensitiveDataExfiltrationAttempts = dataSharingSignals.Count(s => s.Security?.Contains("SENSITIVE DATA EXFILTRATION") == true);
        }
        
        private void ProcessUnauthorizedCloudStorageFeatures(BehavioralFeatures features, List<SignalEventLog> cloudStorageSignals)
        {
            features.PersonalCloudStorageUsed = cloudStorageSignals.Any(s => s.Security?.Contains("PERSONAL CLOUD STORAGE") == true);
            features.UnapprovedCloudServiceDetected = cloudStorageSignals.Any(s => s.Security?.Contains("UNAPPROVED CLOUD SERVICE") == true);
            features.UnencryptedCloudStorageAccess = cloudStorageSignals.Any(s => s.Security?.Contains("UNENCRYPTED CLOUD STORAGE") == true);
            features.CloudStoragePolicyViolation = cloudStorageSignals.Any(s => s.Security?.Contains("CLOUD STORAGE POLICY VIOLATION") == true);
            
            features.PersonalCloudSyncCount = cloudStorageSignals.Count(s => s.Security?.Contains("PERSONAL CLOUD SYNC") == true);
            features.UnapprovedCloudUploadCount = cloudStorageSignals.Count(s => s.Security?.Contains("UNAPPROVED CLOUD UPLOAD") == true);
        }
        
        private void ProcessBluetoothFeatures(BehavioralFeatures features, List<SignalEventLog> bluetoothSignals)
        {
            var latest = bluetoothSignals.LastOrDefault();
            if (latest != null)
            {
                features.BluetoothEnabled = latest.IsConnected ?? false;
                features.BluetoothDeviceCount = latest.VpnConnectionCount ?? 0;
                features.UnauthorizedBluetoothDevice = latest.HipaaViolation ?? false;
            }
        }
        
        private void ProcessSystemInfoFeatures(BehavioralFeatures features, List<SignalEventLog> systemInfoSignals)
        {
            // System info (OS, architecture, model) is already captured in BehavioralFeatures constructor
            // This method processes any additional system-related signals if needed
        }

        private double CalculateStdDev(IEnumerable<double> values)
        {
            var list = values.ToList();
            if (!list.Any()) return 0;
            
            var avg = list.Average();
            var variance = list.Average(v => Math.Pow(v - avg, 2));
            return Math.Sqrt(variance);
        }

        private int CalculateScreenRegion(int x, int y)
        {
            // Assume 1920x1080 screen, divide into 3x3 grid
            var regionX = x < 640 ? 0 : x < 1280 ? 1 : 2;
            var regionY = y < 360 ? 0 : y < 720 ? 1 : 2;
            return regionY * 3 + regionX;
        }

        private async Task WriteCsvAsync(BehavioralFeatures features)
        {
            var csv = features.ToCsvRow();
            
            if (!File.Exists(_csvOutputPath))
            {
                await File.WriteAllTextAsync(_csvOutputPath, BehavioralFeatures.CsvHeader + Environment.NewLine);
            }
            
            await File.AppendAllTextAsync(_csvOutputPath, csv + Environment.NewLine);
        }

        private async Task SendToServiceBusAsync(BehavioralFeatures features)
        {
            if (_serviceBusClient == null || _tenantService == null) return;

            try
            {
                var tenantId = await _tenantService.GetTenantIdAsync();
                var topicName = await _tenantService.GetServiceBusTopicAsync(tenantId);
                
                _sender ??= _serviceBusClient.CreateSender(topicName);
                
                var message = new ServiceBusMessage(JsonSerializer.Serialize(features))
                {
                    ContentType = "application/json",
                    MessageId = Guid.NewGuid().ToString()
                };
                
                // Fire and forget - don't await to speed up processing
                _ = Task.Run(async () => 
                {
                    try { await _sender.SendMessageAsync(message); }
                    catch { /* Ignore send failures */ }
                });
            }
            catch { /* Service Bus unavailable */ }
        }

        private async Task<bool> IsInternetAvailableAsync()
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync("8.8.8.8", 3000);
                return reply.Status == IPStatus.Success;
            }
            catch { return false; }
        }

        public void Dispose()
        {
            _sender?.DisposeAsync();
            _serviceBusClient?.DisposeAsync();
        }
    }
}