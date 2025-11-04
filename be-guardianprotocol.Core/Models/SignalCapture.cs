using be_guardianprotocol.Core.Enums;

namespace be_guardianprotocol.Core.Models
{
    public class SignalCapture
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public SignalTypes Type { get; set; }
        public string? Name { get; set; }
        public string? MacAddress { get; set; }
        public string? Frequency { get; set; }
        public string? Interface { get; set; }
        public string? Mode { get; set; }
        public double? Strength { get; set; }
        public string? IPAddress { get; set; }
        public string? Security { get; set; }
        public bool IsConnected { get; set; }
        public DateTime? ConnectionTime { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        
        // Mouse-specific properties
        public string? DeviceName { get; set; }
        public string? ConnectionType { get; set; }
        public int? DeltaX { get; set; }
        public int? DeltaY { get; set; }
        public int? PositionX { get; set; }
        public int? PositionY { get; set; }
        public int? ScrollDelta { get; set; }
        public string? Button { get; set; }
        public string? ButtonState { get; set; }
        public string? ClickType { get; set; }
        public double? MovementSpeed { get; set; }
        public bool? IsDragging { get; set; }
        public string? ActiveWindow { get; set; }
        public string? MovementDirection { get; set; }
        public string? ActivityType { get; set; }
        public double? DistanceTraveled { get; set; }
        public string? ScreenRegion { get; set; }
        public bool? IsIdle { get; set; }
        public string? BehaviorPattern { get; set; }
        
        // USB-specific properties
        public string? USBDeviceID { get; set; }
        public string? VendorID { get; set; }
        public string? ProductID { get; set; }
        public string? USBVersion { get; set; }
        public string? SerialNumber { get; set; }
        public string? DeviceClass { get; set; }
        public string? PowerState { get; set; }
        public string? TransferSpeed { get; set; }
        public string? EventType { get; set; }
        
        // Keyboard-specific properties
        public string? KeyPressed { get; set; }
        public string? KeyState { get; set; }
        public int? KeyCode { get; set; }
        public bool? IsModifierKey { get; set; }
        public string? ModifierKeys { get; set; }
        public string? KeyCategory { get; set; }
        public int? TypingSpeed { get; set; }
        public string? InputPattern { get; set; }
        public int? ErrorCount { get; set; }
        public bool? IsRepeatKey { get; set; }
        public bool? IsLongPress { get; set; }
        public bool? IsCapsLock { get; set; }
        public bool? IsNumLock { get; set; }
        public bool? IsScrollLock { get; set; }
        public double? PressDuration { get; set; }
        public double? TimeSinceLastKey { get; set; }
        public string? LanguageLayout { get; set; }
        public bool? IsVirtualKeyboard { get; set; }
        public bool? IsSecureInputField { get; set; }
        public double? SystemIdleTime { get; set; }
        
        // Advanced Keyboard Analytics
        // Temporal/Timing Properties
        public double? KeyPressDuration { get; set; }
        public double? InterKeyDelay { get; set; }
        public double? Burstiness { get; set; }
        public double? TypingLatency { get; set; }
        public double? AverageBurstDuration { get; set; }
        public double? IdleTime { get; set; }
        
        // Positional/Contextual Properties
        public string? RowPosition { get; set; }
        public string? HandUsed { get; set; }
        public string? FingerUsed { get; set; }
        public double? KeyDistance { get; set; }
        
        // Behavioral/Derived Metrics
        public double? TypingConsistency { get; set; }
        public double? ErrorRate { get; set; }
        public double? BurstinessIndex { get; set; }
        public double? TypingPressure { get; set; }
        public double? PredictiveConfidence { get; set; }
        
        // Keyboard Dynamics Properties
        public double? InterKeyLatency { get; set; }
        public double? KeystrokeBurstiness { get; set; }
        public double? ErrorUndoRate { get; set; }
        public int? LayoutChangeCount { get; set; }
        
        // Process/Application Properties
        public string? ProcessName { get; set; }
        public int? ProcessId { get; set; }
        public string? CurrentApp { get; set; }
        public string? PreviousApp { get; set; }
        public int? AppSwitchCount { get; set; }
        public double? AppForegroundTime { get; set; }
        public int? ActiveProcessCount { get; set; }
        public int? TotalProcessCount { get; set; }
        public int? CurrentAppProcessCount { get; set; }
        
        // System Performance Properties
        public double? SystemCpuUsage { get; set; }
        public double? SystemMemoryUsage { get; set; }
        public double? CurrentAppCpuUsage { get; set; }
        public long? CurrentAppMemoryUsage { get; set; }
        
        // Network Traffic Properties
        public long? BytesReceived { get; set; }
        public long? BytesSent { get; set; }
        public double? BytesReceivedRate { get; set; }
        public double? BytesSentRate { get; set; }
        public int? ActiveNetworkInterfaces { get; set; }
        public string? NetworkInterfaceNames { get; set; }
        public long? TotalNetworkActivity { get; set; }
        public double? NetworkUtilization { get; set; }
        
        // Text Analysis Properties
        public int? WordCount { get; set; }
        public double? AverageWordLength { get; set; }
        public double? WordLengthStdDev { get; set; }
        public int? WordLength1Count { get; set; }
        public int? WordLength2Count { get; set; }
        public int? WordLength3Count { get; set; }
        public int? WordLength4Count { get; set; }
        public int? WordLength5Count { get; set; }
        public int? WordLength6Count { get; set; }
        public int? WordLength7Count { get; set; }
        public int? WordLength8Count { get; set; }
        public int? WordLength9Count { get; set; }
        public int? WordLength10Count { get; set; }
        public int? WordLength11PlusCount { get; set; }
        public string? TypingPattern { get; set; }
        public string? LanguagePattern { get; set; }
        public double? TextComplexity { get; set; }
        
        // Bluetooth-specific properties
        public int? DeviceCount { get; set; }
        public string? ConnectedDevices { get; set; }
        public bool? BluetoothEnabled { get; set; }
        public int? NearbyDeviceCount { get; set; }
        public int? PairedDeviceCount { get; set; }
        public string? ErrorMessage { get; set; }
        
        // VPN-specific properties
        public string? VpnConnectionName { get; set; }
        public string? VpnServerAddress { get; set; }
        public string? VpnProtocol { get; set; }
        public bool? IsUntrustedNetwork { get; set; }
        public string? NetworkSSID { get; set; }
        public string? NetworkSecurity { get; set; }
        public int? VpnConnectionCount { get; set; }
        public bool? CorporateVpnDetected { get; set; }
        public string? VpnEventType { get; set; }
        public double? VpnConnectionDuration { get; set; }
        public bool? EncryptionEnabled { get; set; }
        public string? EncryptionMethod { get; set; }
        public double? EncryptionPercentage { get; set; }
        public bool? TmpEnabled { get; set; }
        public string? TmpVersion { get; set; }
        public int? EncryptedVolumeCount { get; set; }
        public int? UnencryptedVolumeCount { get; set; }
        public bool? HipaaViolation { get; set; }
        public string? ComplianceRule { get; set; }
        public string? MitreTactic { get; set; }
        public string? MitreTechnique { get; set; }
        public string? ThreatDetected { get; set; }
        public string? RemoteIP { get; set; }
        public bool? IsBusinessHours { get; set; }
        public int? FailedLogonCount { get; set; }
        
        // Application Security Properties
        public string? ProcessPath { get; set; }
        public string? RemoteAddress { get; set; }
        public int? RemotePort { get; set; }
    }
}
