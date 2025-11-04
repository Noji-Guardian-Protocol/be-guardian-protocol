using System;

namespace be_guardianprotocol.Core.Models
{
    public class SignalEventLog
    {
        public string SignalType { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string? KeyPressed { get; set; }
        public double? InterKeyLatency { get; set; }
        public int? PositionX { get; set; }
        public int? PositionY { get; set; }
        public string? Button { get; set; }
        public int? ActiveProcessCount { get; set; }
        public string? CurrentApp { get; set; }
        public string? PreviousApp { get; set; }
        public int? AppSwitchCount { get; set; }
        public double? AppForegroundTime { get; set; }
        public double? SystemCpuUsage { get; set; }
        public double? SystemMemoryUsage { get; set; }
        public double? CurrentAppCpuUsage { get; set; }
        public long? CurrentAppMemoryUsage { get; set; }
        public long? BytesReceived { get; set; }
        public long? BytesSent { get; set; }
        public int? WordCount { get; set; }
        public double? AverageWordLength { get; set; }
        public bool? IsConnected { get; set; }
        public bool? CorporateVpnDetected { get; set; }
        public bool? IsUntrustedNetwork { get; set; }
        public bool? HipaaViolation { get; set; }
        public int? VpnConnectionCount { get; set; }
        public bool? EncryptionEnabled { get; set; }
        public string? EncryptionMethod { get; set; }
        public bool? TmpEnabled { get; set; }
        public int? EncryptedVolumeCount { get; set; }
        public int? UnencryptedVolumeCount { get; set; }
        public string? Security { get; set; }
        public double? Strength { get; set; }
        public string? ClickType { get; set; }
        public string? EventType { get; set; }
        public string? ProcessName { get; set; }
        public string? Details { get; set; }
    }
}