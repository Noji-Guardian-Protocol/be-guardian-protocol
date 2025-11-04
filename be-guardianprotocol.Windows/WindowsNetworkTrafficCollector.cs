using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Services;

namespace be_guardianprotocol.Windows
{
    public class WindowsNetworkTrafficCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private static long _previousBytesReceived = 0;
        private static long _previousBytesSent = 0;
        private static DateTime _lastMeasurement = DateTime.Now;

        public WindowsNetworkTrafficCollector()
        {
            _logger = new NetworkConnectionLogger();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.OperationalStatus == OperationalStatus.Up && 
                                ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .ToList();

                long totalBytesReceived = 0;
                long totalBytesSent = 0;
                var activeConnections = new List<string>();

                foreach (var ni in networkInterfaces)
                {
                    var stats = ni.GetIPv4Statistics();
                    totalBytesReceived += stats.BytesReceived;
                    totalBytesSent += stats.BytesSent;
                    
                    if (stats.BytesReceived > 0 || stats.BytesSent > 0)
                        activeConnections.Add(ni.Name);
                }

                var timeDiff = (DateTime.Now - _lastMeasurement).TotalSeconds;
                var bytesReceivedRate = timeDiff > 0 ? (totalBytesReceived - _previousBytesReceived) / timeDiff : 0;
                var bytesSentRate = timeDiff > 0 ? (totalBytesSent - _previousBytesSent) / timeDiff : 0;

                var capture = new SignalCapture
                {
                    Type = SignalTypes.Network,
                    IsConnected = networkInterfaces.Any(),
                    Timestamp = DateTime.Now,
                    
                    // Network traffic
                    BytesReceived = totalBytesReceived,
                    BytesSent = totalBytesSent,
                    BytesReceivedRate = bytesReceivedRate,
                    BytesSentRate = bytesSentRate,
                    
                    // Connection info
                    ActiveNetworkInterfaces = activeConnections.Count,
                    NetworkInterfaceNames = string.Join(", ", activeConnections),
                    
                    // Network performance
                    TotalNetworkActivity = totalBytesReceived + totalBytesSent,
                    NetworkUtilization = CalculateNetworkUtilization(bytesReceivedRate + bytesSentRate)
                };

                _previousBytesReceived = totalBytesReceived;
                _previousBytesSent = totalBytesSent;
                _lastMeasurement = DateTime.Now;

                await _logger.LogConnectionAsync(capture);
                results.Add(capture);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Network traffic collection error: {ex.Message}");
            }

            return results;
        }

        private double CalculateNetworkUtilization(double bytesPerSecond)
        {
            // Assume 100 Mbps connection (12.5 MB/s)
            var maxBytesPerSecond = 12.5 * 1024 * 1024;
            return Math.Min(100, (bytesPerSecond / maxBytesPerSecond) * 100);
        }
    }
}