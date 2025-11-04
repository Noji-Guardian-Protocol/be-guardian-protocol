using be_guardianprotocol.Core.Models;
using System.Text.Json;

namespace be_guardianprotocol.Core.Services
{
    public class KeyboardDynamicsAnalyzer
    {
        private readonly string _profilePath;
        private readonly List<double> _interKeyLatencies = new();
        private readonly List<double> _burstinessValues = new();
        private readonly List<DateTime> _keyEvents = new();
        private int _errorCount = 0;
        private int _undoCount = 0;
        private int _totalKeyEvents = 0;
        private string _currentLayout = "en-US";
        private int _layoutChanges = 0;
        private DateTime _sessionStart = DateTime.UtcNow;

        public KeyboardDynamicsAnalyzer()
        {
            _profilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "GuardianProtocol", "keyboard_dynamics.json");
            Directory.CreateDirectory(Path.GetDirectoryName(_profilePath)!);
        }

        public void ProcessKeyEvent(bool isErrorKey, bool isUndoKey, double interKeyLatency, string currentLayout)
        {
            _totalKeyEvents++;
            
            // Track inter-key latency (anonymized timing only)
            if (interKeyLatency > 0 && interKeyLatency < 5000) // Filter outliers
            {
                _interKeyLatencies.Add(interKeyLatency);
                if (_interKeyLatencies.Count > 1000) // Keep recent history
                    _interKeyLatencies.RemoveAt(0);
            }
            
            // Track error/undo events (no content, just counts)
            if (isErrorKey) _errorCount++;
            if (isUndoKey) _undoCount++;
            
            // Track layout changes
            if (currentLayout != _currentLayout)
            {
                _layoutChanges++;
                _currentLayout = currentLayout;
            }
            
            // Track burstiness in 5-second windows
            var now = DateTime.UtcNow;
            _keyEvents.Add(now);
            _keyEvents.RemoveAll(t => (now - t).TotalSeconds > 5);
            
            if (_keyEvents.Count > 1)
            {
                var burstiness = _keyEvents.Count / 5.0; // Keys per second
                _burstinessValues.Add(burstiness);
                if (_burstinessValues.Count > 200) // Keep recent history
                    _burstinessValues.RemoveAt(0);
            }
        }

        public KeyboardDynamicsProfile GenerateAnonymizedProfile()
        {
            var profile = new KeyboardDynamicsProfile
            {
                SessionStart = _sessionStart,
                LastUpdate = DateTime.UtcNow,
                CurrentLayout = _currentLayout,
                LayoutChanges = _layoutChanges,
                SampleCount = _totalKeyEvents
            };

            // Compute inter-key latency metrics (anonymized)
            if (_interKeyLatencies.Count > 0)
            {
                profile.AvgInterKeyLatency = _interKeyLatencies.Average();
                profile.StdDevInterKeyLatency = CalculateStandardDeviation(_interKeyLatencies);
                profile.MedianInterKeyLatency = CalculateMedian(_interKeyLatencies);
            }

            // Compute burstiness metrics
            if (_burstinessValues.Count > 0)
            {
                profile.AvgBurstiness = _burstinessValues.Average();
                profile.MaxBurstiness = _burstinessValues.Max();
                profile.BurstFrequency = _burstinessValues.Count(b => b > profile.AvgBurstiness * 1.5) / (double)_burstinessValues.Count;
            }

            // Compute error/undo rates (anonymized ratios only)
            if (_totalKeyEvents > 0)
            {
                profile.ErrorRate = (double)_errorCount / _totalKeyEvents;
                profile.UndoRate = (double)_undoCount / _totalKeyEvents;
                profile.CorrectionRatio = _errorCount > 0 ? (double)_undoCount / _errorCount : 0;
            }

            // Compute typing consistency
            profile.TypingConsistency = profile.StdDevInterKeyLatency > 0 ? 
                1.0 - Math.Min(1.0, profile.StdDevInterKeyLatency / profile.AvgInterKeyLatency) : 1.0;

            // Generate anonymized behavioral vector for ML
            profile.BehavioralVector = GenerateBehavioralVector(profile);

            return profile;
        }

        private double[] GenerateBehavioralVector(KeyboardDynamicsProfile profile)
        {
            // Create anonymized feature vector for ML (no sensitive data)
            return new double[]
            {
                NormalizeValue(profile.AvgInterKeyLatency, 0, 500),           // 0: Avg timing
                NormalizeValue(profile.StdDevInterKeyLatency, 0, 200),       // 1: Timing variance
                NormalizeValue(profile.AvgBurstiness, 0, 10),                // 2: Avg burst rate
                NormalizeValue(profile.MaxBurstiness, 0, 20),                // 3: Max burst rate
                NormalizeValue(profile.ErrorRate, 0, 0.2),                   // 4: Error frequency
                NormalizeValue(profile.UndoRate, 0, 0.1),                    // 5: Correction frequency
                NormalizeValue(profile.CorrectionRatio, 0, 2),               // 6: Correction efficiency
                NormalizeValue(profile.TypingConsistency, 0, 1),             // 7: Consistency score
                NormalizeValue(profile.BurstFrequency, 0, 1),                // 8: Burst pattern
                NormalizeValue(profile.LayoutChanges, 0, 10)                 // 9: Layout switching
            };
        }

        private static double NormalizeValue(double value, double min, double max)
        {
            return Math.Max(0, Math.Min(1, (value - min) / (max - min)));
        }

        private static double CalculateStandardDeviation(List<double> values)
        {
            var avg = values.Average();
            return Math.Sqrt(values.Select(x => Math.Pow(x - avg, 2)).Average());
        }

        private static double CalculateMedian(List<double> values)
        {
            var sorted = values.OrderBy(x => x).ToList();
            var mid = sorted.Count / 2;
            return sorted.Count % 2 == 0 ? (sorted[mid - 1] + sorted[mid]) / 2.0 : sorted[mid];
        }

        public async Task SaveProfileAsync(KeyboardDynamicsProfile profile)
        {
            try
            {
                var json = JsonSerializer.Serialize(profile, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_profilePath, json);
            }
            catch
            {
                // Silent fail for profile saving
            }
        }

        public async Task<KeyboardDynamicsProfile?> LoadProfileAsync()
        {
            try
            {
                if (File.Exists(_profilePath))
                {
                    var json = await File.ReadAllTextAsync(_profilePath);
                    return JsonSerializer.Deserialize<KeyboardDynamicsProfile>(json);
                }
            }
            catch
            {
                // Silent fail for profile loading
            }
            return null;
        }
    }
}