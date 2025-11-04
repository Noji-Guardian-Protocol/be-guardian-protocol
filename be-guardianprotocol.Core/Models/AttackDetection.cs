namespace be_guardianprotocol.Core.Models
{
    public class AttackDetection
    {
        public string TacticId { get; set; } = "";
        public string TechniqueId { get; set; } = "";
        public string TechniqueName { get; set; } = "";
        public string Description { get; set; } = "";
        public bool IsDetected { get; set; }
        public DateTime DetectionTime { get; set; }
        public string Evidence { get; set; } = "";
        public string Severity { get; set; } = "";
    }

    public class DetectionParameters
    {
        public List<string> KnownRemoteIPs { get; set; } = new();
        public List<string> BusinessHours { get; set; } = new() { "08:00-18:00" };
        public int FailedLogonThreshold { get; set; } = 5;
        public List<string> GeoIPWhitelist { get; set; } = new();
        public int TimeWindowMinutes { get; set; } = 15;
        public List<string> ApprovedVpnEndpoints { get; set; } = new();
    }
}