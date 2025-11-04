using Azure.Messaging.ServiceBus;
using be_guardianprotocol.Core.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace be_guardianprotocol.Core.Services
{
    public class ServiceBusPublisher : BackgroundService
    {
        private readonly ServiceBusClient _client;
        private readonly ServiceBusSender _sender;
        private readonly ILogger<ServiceBusPublisher> _logger;
        private readonly FeatureExtractionEngine _featureEngine;

        public ServiceBusPublisher(string connectionString, string topicName, FeatureExtractionEngine featureEngine, ILogger<ServiceBusPublisher> logger)
        {
            _client = new ServiceBusClient(connectionString);
            _sender = _client.CreateSender(topicName);
            _featureEngine = featureEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var features = await _featureEngine.ExtractFeaturesAsync();
                    var message = new ServiceBusMessage(JsonSerializer.Serialize(features))
                    {
                        Subject = $"behavioral-features/{features.UserId}",
                        ContentType = "application/json"
                    };

                    await _sender.SendMessageAsync(message, stoppingToken);
                    _logger.LogInformation("Successfully sent behavioral features to topic g-pro for user {UserId} at {Timestamp}. Features: Keystrokes={KeystrokeCounter}, VPN={VpnConnected}, HIPAA Violations={HipaaViolationDetected}", 
                        features.UserId, DateTime.UtcNow, features.KeystrokeCounter, features.VpnConnected, features.HipaaViolationDetected);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to publish behavioral features");
                }
                
                await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);
            }
        }

        public override void Dispose()
        {
            _sender?.DisposeAsync().AsTask().Wait();
            _client?.DisposeAsync().AsTask().Wait();
            base.Dispose();
        }
    }
}