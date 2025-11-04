namespace be_guardianprotocol.Core.Models
{
    public class KeyboardDynamicsProfile
    {
        public string UserId { get; set; } = Environment.UserName;
        public DateTime SessionStart { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdate { get; set; } = DateTime.UtcNow;
        
        // Inter-key latency metrics (anonymized)
        public double AvgInterKeyLatency { get; set; }
        public double StdDevInterKeyLatency { get; set; }
        public double MedianInterKeyLatency { get; set; }
        
        // Burstiness metrics
        public double AvgBurstiness { get; set; }
        public double MaxBurstiness { get; set; }
        public double BurstFrequency { get; set; }
        
        // Error/Undo rate metrics
        public double ErrorRate { get; set; }
        public double UndoRate { get; set; }
        public double CorrectionRatio { get; set; }
        
        // Layout and behavioral patterns
        public string CurrentLayout { get; set; } = "en-US";
        public int LayoutChanges { get; set; }
        public double TypingConsistency { get; set; }
        
        // Anonymized behavioral vectors
        public double[] BehavioralVector { get; set; } = new double[10];
        public int SampleCount { get; set; }
    }
}