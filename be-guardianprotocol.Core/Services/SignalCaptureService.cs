using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;

namespace be_guardianprotocol.Core.Services
{
    public class SignalCaptureService
    {
        private readonly ISignalCollector _collector;

        public SignalCaptureService(ISignalCollector collector)
        {
            _collector = collector;
        }

        public async Task RunAsync()
        {
            var signals = (await _collector.CollectAsync()).ToList();

            Console.Clear();
            Console.WriteLine($"[{DateTime.Now}] Captured {signals.Count} WiFi signal(s)\n");

            foreach (var s in signals)
            {
                if (s.IsConnected)
                    Console.ForegroundColor = ConsoleColor.Green;
                else
                    Console.ResetColor();

                if (s.Type == SignalTypes.Wifi)
                {
                    Console.WriteLine($"📶 SSID: {s.Name ?? "N/A"}");
                    Console.WriteLine($"   BSSID: {s.MacAddress ?? "N/A"}");
                    Console.WriteLine($"   Signal: {s.Strength?.ToString("F0") ?? "N/A"}%");
                    Console.WriteLine($"   Frequency: {s.Frequency ?? "N/A"}");
                    Console.WriteLine($"   Interface: {s.Interface ?? "N/A"}");
                    Console.WriteLine($"   Mode: {s.Mode ?? "N/A"}");
                    Console.WriteLine($"   Security: {s.Security ?? "N/A"}");
                    if (!string.IsNullOrWhiteSpace(s.IPAddress))
                        Console.WriteLine($"   IP Address: {s.IPAddress}");
                    if (s.ConnectionTime.HasValue)
                        Console.WriteLine($"   Connection Time: {s.ConnectionTime.Value:yyyy-MM-dd HH:mm:ss}");
                }
                else if (s.Type == SignalTypes.Mouse)
                {
                    Console.WriteLine($"🖘 Device: {s.DeviceName ?? "N/A"}");
                    Console.WriteLine($"   Connection: {s.ConnectionType ?? "N/A"}");
                    Console.WriteLine($"   Position: ({s.PositionX ?? 0}, {s.PositionY ?? 0})");
                    Console.WriteLine($"   Movement: (Δ{s.DeltaX ?? 0}, Δ{s.DeltaY ?? 0})");
                    Console.WriteLine($"   Speed: {s.MovementSpeed?.ToString("F1") ?? "0"} px/s");
                    if (!string.IsNullOrWhiteSpace(s.Button))
                        Console.WriteLine($"   Button: {s.Button} ({s.ButtonState})");
                    if (!string.IsNullOrWhiteSpace(s.ActiveWindow))
                        Console.WriteLine($"   Active Window: {s.ActiveWindow}");
                }
                else if (s.Type == SignalTypes.USB)
                {
                    Console.WriteLine($"🔌 USB: {s.Name ?? "N/A"}");
                    Console.WriteLine($"   Device ID: {s.USBDeviceID ?? "N/A"}");
                    Console.WriteLine($"   VID/PID: {s.VendorID ?? "N/A"}/{s.ProductID ?? "N/A"}");
                    Console.WriteLine($"   Class: {s.DeviceClass ?? "N/A"}");
                    Console.WriteLine($"   Speed: {s.TransferSpeed ?? "N/A"}");
                    Console.WriteLine($"   Event: {s.EventType ?? "N/A"}");
                    Console.WriteLine($"   Power: {s.PowerState ?? "N/A"}");
                    if (s.ConnectionTime.HasValue)
                        Console.WriteLine($"   Connection Time: {s.ConnectionTime.Value:yyyy-MM-dd HH:mm:ss}");
                }
                else if (s.Type == SignalTypes.Keyboard)
                {
                    Console.WriteLine($"⌨️ Key: {s.KeyPressed ?? "N/A"}");
                    Console.WriteLine($"   Device: {s.DeviceName ?? "N/A"}");
                    Console.WriteLine($"   Connection: {s.ConnectionType ?? "N/A"}");
                    Console.WriteLine($"   Category: {s.KeyCategory ?? "N/A"}");
                    Console.WriteLine($"   Pattern: {s.InputPattern ?? "N/A"}");
                    if (!string.IsNullOrWhiteSpace(s.ModifierKeys))
                        Console.WriteLine($"   Modifiers: {s.ModifierKeys}");
                    Console.WriteLine($"   Typing Speed: {s.TypingSpeed ?? 0} keys/min");
                    if (s.InterKeyLatency.HasValue)
                        Console.WriteLine($"   Inter-Key Latency: {s.InterKeyLatency.Value:F1}ms");
                    if (s.KeystrokeBurstiness.HasValue)
                        Console.WriteLine($"   Burstiness: {s.KeystrokeBurstiness.Value:F1} keys/sec");
                    if (s.ErrorUndoRate.HasValue)
                        Console.WriteLine($"   Error Rate: {s.ErrorUndoRate.Value:F3}");
                    if (s.LayoutChangeCount.HasValue)
                        Console.WriteLine($"   Layout Changes: {s.LayoutChangeCount.Value}");
                    if (!string.IsNullOrWhiteSpace(s.ActiveWindow))
                        Console.WriteLine($"   Active Window: {s.ActiveWindow}");
                }
                else if (s.Type == SignalTypes.Process)
                {
                    Console.WriteLine($"💻 Process: {s.ProcessName ?? "N/A"}");
                    Console.WriteLine($"   Current App: {s.CurrentApp ?? "N/A"}");
                    Console.WriteLine($"   Previous App: {s.PreviousApp ?? "N/A"}");
                    Console.WriteLine($"   App Switches: {s.AppSwitchCount ?? 0}");
                    Console.WriteLine($"   Foreground Time: {s.AppForegroundTime?.ToString("F1") ?? "0"}s");
                    Console.WriteLine($"   Active Processes: {s.ActiveProcessCount ?? 0}");
                    Console.WriteLine($"   System CPU: {s.SystemCpuUsage?.ToString("F1") ?? "0"}%");
                    Console.WriteLine($"   System Memory: {s.SystemMemoryUsage?.ToString("F1") ?? "0"} MB");
                    Console.WriteLine($"   App CPU: {s.CurrentAppCpuUsage?.ToString("F1") ?? "0"}ms");
                    Console.WriteLine($"   App Memory: {s.CurrentAppMemoryUsage ?? 0} MB");
                }
                else if (s.Type == SignalTypes.Network)
                {
                    Console.WriteLine($"🌐 Network Traffic");
                    Console.WriteLine($"   Bytes Received: {s.BytesReceived ?? 0:N0}");
                    Console.WriteLine($"   Bytes Sent: {s.BytesSent ?? 0:N0}");
                    Console.WriteLine($"   Receive Rate: {s.BytesReceivedRate?.ToString("F1") ?? "0"} B/s");
                    Console.WriteLine($"   Send Rate: {s.BytesSentRate?.ToString("F1") ?? "0"} B/s");
                    Console.WriteLine($"   Active Interfaces: {s.ActiveNetworkInterfaces ?? 0}");
                    Console.WriteLine($"   Utilization: {s.NetworkUtilization?.ToString("F1") ?? "0"}%");
                    if (!string.IsNullOrWhiteSpace(s.NetworkInterfaceNames))
                        Console.WriteLine($"   Interfaces: {s.NetworkInterfaceNames}");
                }
                else if (s.Type == SignalTypes.TextAnalysis)
                {
                    Console.WriteLine($"📝 Text Analysis");
                    Console.WriteLine($"   Words: {s.WordCount ?? 0}");
                    Console.WriteLine($"   Avg Word Length: {s.AverageWordLength?.ToString("F1") ?? "0"}");
                    Console.WriteLine($"   Typing Pattern: {s.TypingPattern ?? "N/A"}");
                    Console.WriteLine($"   Language: {s.LanguagePattern ?? "N/A"}");
                    Console.WriteLine($"   Complexity: {s.TextComplexity?.ToString("F2") ?? "0"}");
                    Console.WriteLine($"   Word Lengths: 1-3:{s.WordLength1Count ?? 0 + s.WordLength2Count ?? 0 + s.WordLength3Count ?? 0} 4-6:{s.WordLength4Count ?? 0 + s.WordLength5Count ?? 0 + s.WordLength6Count ?? 0} 7+:{s.WordLength7Count ?? 0 + s.WordLength8Count ?? 0 + s.WordLength9Count ?? 0 + s.WordLength10Count ?? 0 + s.WordLength11PlusCount ?? 0}");
                }
                
                Console.WriteLine($"   Connected: {s.IsConnected}");
                Console.WriteLine();
            }

            Console.ResetColor();
        }
    }
}