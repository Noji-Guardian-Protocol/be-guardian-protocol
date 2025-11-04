using be_guardianprotocol.Core.Models;
using System.Text.Json;

namespace be_guardianprotocol.Core.Services
{
    public class NetworkConnectionLogger
    {
        private readonly string _logFilePath;
        private static readonly Dictionary<string, int> _untrustedConnections = new();

        public NetworkConnectionLogger()
        {
            _logFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                "GuardianProtocol", "signal_events.json");
            Directory.CreateDirectory(Path.GetDirectoryName(_logFilePath)!);
        }

        public void LogSignal(be_guardianprotocol.Core.Models.SignalEventLog signal)
        {
            try
            {
                var json = JsonSerializer.Serialize(signal) + Environment.NewLine;
                File.AppendAllText(_logFilePath, json);
            }
            catch
            {
                // Silent fail for logging
            }
        }
        
        public async Task LogConnectionAsync(SignalCapture signal)
        {
            var logEntry = new SignalEventLog
            {
                Timestamp = DateTime.UtcNow,
                SignalType = signal.Type.ToString(),
                SSID = signal.Name,
                BSSID = signal.MacAddress,
                Security = signal.Security,
                IsUntrusted = IsUntrustedNetwork(signal),
                IPAddress = signal.IPAddress,
                DeviceName = signal.DeviceName,
                ConnectionType = signal.ConnectionType,
                PositionX = signal.PositionX,
                PositionY = signal.PositionY,
                Button = signal.Button,
                ButtonState = signal.ButtonState,
                ActiveWindow = signal.ActiveWindow,
                MovementDirection = signal.MovementDirection,
                ActivityType = signal.ActivityType,
                DistanceTraveled = signal.DistanceTraveled,
                ScreenRegion = signal.ScreenRegion,
                IsIdle = signal.IsIdle,
                BehaviorPattern = signal.BehaviorPattern,
                ClickType = signal.ClickType,
                IsDragging = signal.IsDragging,
                
                // Keyboard properties
                KeyPressed = signal.KeyPressed,
                KeyState = signal.KeyState,
                KeyCode = signal.KeyCode,
                IsModifierKey = signal.IsModifierKey,
                ModifierKeys = signal.ModifierKeys,
                KeyCategory = signal.KeyCategory,
                TypingSpeed = signal.TypingSpeed,
                InputPattern = signal.InputPattern,
                InterKeyLatency = signal.InterKeyLatency,
                KeystrokeBurstiness = signal.KeystrokeBurstiness,
                ErrorUndoRate = signal.ErrorUndoRate,
                LayoutChangeCount = signal.LayoutChangeCount,
                
                // Process properties
                ProcessName = signal.ProcessName,
                ProcessId = signal.ProcessId,
                CurrentApp = signal.CurrentApp,
                PreviousApp = signal.PreviousApp,
                AppSwitchCount = signal.AppSwitchCount,
                AppForegroundTime = signal.AppForegroundTime,
                ActiveProcessCount = signal.ActiveProcessCount,
                SystemCpuUsage = signal.SystemCpuUsage,
                SystemMemoryUsage = signal.SystemMemoryUsage,
                CurrentAppCpuUsage = signal.CurrentAppCpuUsage,
                CurrentAppMemoryUsage = signal.CurrentAppMemoryUsage,
                
                // Network properties
                BytesReceived = signal.BytesReceived,
                BytesSent = signal.BytesSent,
                BytesReceivedRate = signal.BytesReceivedRate,
                BytesSentRate = signal.BytesSentRate,
                ActiveNetworkInterfaces = signal.ActiveNetworkInterfaces,
                NetworkUtilization = signal.NetworkUtilization,
                
                // Text analysis properties
                WordCount = signal.WordCount,
                AverageWordLength = signal.AverageWordLength,
                TypingPattern = signal.TypingPattern,
                LanguagePattern = signal.LanguagePattern,
                TextComplexity = signal.TextComplexity,
                
                // VPN properties
                IsConnected = signal.IsConnected,
                CorporateVpnDetected = signal.CorporateVpnDetected,
                IsUntrustedNetwork = signal.IsUntrustedNetwork,
                HipaaViolation = signal.HipaaViolation,
                VpnConnectionCount = signal.VpnConnectionCount,
                
                // Encryption properties
                EncryptionEnabled = signal.EncryptionEnabled,
                EncryptionMethod = signal.EncryptionMethod,
                EncryptionPercentage = signal.EncryptionPercentage,
                TmpEnabled = signal.TmpEnabled,
                EncryptedVolumeCount = signal.EncryptedVolumeCount,
                UnencryptedVolumeCount = signal.UnencryptedVolumeCount
            };

            await AppendLogEntryAsync(logEntry);

            if (logEntry.IsUntrusted)
            {
                TrackUntrustedConnection(signal.Name);
            }
        }

        public string CheckRepeatedUntrustedConnections(SignalCapture signal)
        {
            if (!IsUntrustedNetwork(signal)) return string.Empty;

            var key = $"{signal.Name}_{signal.MacAddress}";
            if (_untrustedConnections.TryGetValue(key, out var count) && count >= 3)
            {
                return $" - 🚨 REPEATED UNTRUSTED ({count}x)";
            }

            return string.Empty;
        }

        private static bool IsUntrustedNetwork(SignalCapture signal)
        {
            return signal.Security?.Contains("Insecure", StringComparison.OrdinalIgnoreCase) == true ||
                   signal.Security?.Contains("PUBLIC WIFI", StringComparison.OrdinalIgnoreCase) == true ||
                   signal.Security?.Contains("NO WPA2/WPA3", StringComparison.OrdinalIgnoreCase) == true;
        }

        private static void TrackUntrustedConnection(string? ssid)
        {
            if (string.IsNullOrWhiteSpace(ssid)) return;

            var key = ssid;
            _untrustedConnections[key] = _untrustedConnections.GetValueOrDefault(key, 0) + 1;
        }

        private async Task AppendLogEntryAsync(SignalEventLog entry)
        {
            try
            {
                var json = JsonSerializer.Serialize(entry) + Environment.NewLine;
                await File.AppendAllTextAsync(_logFilePath, json);
            }
            catch
            {
                // Silent fail for logging
            }
        }
    }

    public class SignalEventLog
    {
        public DateTime Timestamp { get; set; }
        public string? SignalType { get; set; }
        public string? SSID { get; set; }
        public string? BSSID { get; set; }
        public string? Security { get; set; }
        public bool IsUntrusted { get; set; }
        public string? IPAddress { get; set; }
        public string? DeviceName { get; set; }
        public string? ConnectionType { get; set; }
        public int? PositionX { get; set; }
        public int? PositionY { get; set; }
        public string? Button { get; set; }
        public string? ButtonState { get; set; }
        public string? ActiveWindow { get; set; }
        public string? MovementDirection { get; set; }
        public string? ActivityType { get; set; }
        public double? DistanceTraveled { get; set; }
        public string? ScreenRegion { get; set; }
        public bool? IsIdle { get; set; }
        public string? BehaviorPattern { get; set; }
        public string? ClickType { get; set; }
        public bool? IsDragging { get; set; }
        
        // Keyboard properties
        public string? KeyPressed { get; set; }
        public string? KeyState { get; set; }
        public int? KeyCode { get; set; }
        public bool? IsModifierKey { get; set; }
        public string? ModifierKeys { get; set; }
        public string? KeyCategory { get; set; }
        public int? TypingSpeed { get; set; }
        public string? InputPattern { get; set; }
        public double? InterKeyLatency { get; set; }
        public double? KeystrokeBurstiness { get; set; }
        public double? ErrorUndoRate { get; set; }
        public int? LayoutChangeCount { get; set; }
        
        // Process properties
        public string? ProcessName { get; set; }
        public int? ProcessId { get; set; }
        public string? CurrentApp { get; set; }
        public string? PreviousApp { get; set; }
        public int? AppSwitchCount { get; set; }
        public double? AppForegroundTime { get; set; }
        public int? ActiveProcessCount { get; set; }
        public double? SystemCpuUsage { get; set; }
        public double? SystemMemoryUsage { get; set; }
        public double? CurrentAppCpuUsage { get; set; }
        public long? CurrentAppMemoryUsage { get; set; }
        
        // Network properties
        public long? BytesReceived { get; set; }
        public long? BytesSent { get; set; }
        public double? BytesReceivedRate { get; set; }
        public double? BytesSentRate { get; set; }
        public int? ActiveNetworkInterfaces { get; set; }
        public double? NetworkUtilization { get; set; }
        
        // Text analysis properties
        public int? WordCount { get; set; }
        public double? AverageWordLength { get; set; }
        public string? TypingPattern { get; set; }
        public string? LanguagePattern { get; set; }
        public double? TextComplexity { get; set; }
        
        // VPN properties
        public bool? IsConnected { get; set; }
        public bool? CorporateVpnDetected { get; set; }
        public bool? IsUntrustedNetwork { get; set; }
        public bool? HipaaViolation { get; set; }
        public int? VpnConnectionCount { get; set; }
        
        // Encryption properties
        public bool? EncryptionEnabled { get; set; }
        public string? EncryptionMethod { get; set; }
        public double? EncryptionPercentage { get; set; }
        public bool? TmpEnabled { get; set; }
        public int? EncryptedVolumeCount { get; set; }
        public int? UnencryptedVolumeCount { get; set; }
    }
}