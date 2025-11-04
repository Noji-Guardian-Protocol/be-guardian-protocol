using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Data;
using be_guardianprotocol.Core.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Text.Json;

namespace be_guardianprotocol.Core.Services
{
    public class GuardianProtocolAgent
    {
        private readonly List<ISignalCollector> _collectors;
        private readonly FeatureExtractionEngine _featureEngine;
        private readonly string _logFilePath;
        private readonly CancellationTokenSource _cancellationTokenSource;

        public GuardianProtocolAgent(IEnumerable<ISignalCollector> collectors, FeatureExtractionEngine featureEngine)
        {
            _collectors = collectors.ToList();
            _featureEngine = featureEngine;
            _logFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                "GuardianProtocol", "signal_events.json");
            _cancellationTokenSource = new CancellationTokenSource();
            
            Directory.CreateDirectory(Path.GetDirectoryName(_logFilePath)!);
        }

        public async Task StartAsync()
        {
            Console.WriteLine("Guardian Protocol Agent started");
            
            await EnsureDatabaseAsync();
            
            Console.WriteLine("Starting signal collection and feature processing loops...");
            var collectionTask = Task.Run(async () => await CollectSignalsAsync(_cancellationTokenSource.Token));
            var processingTask = Task.Run(async () => await ProcessFeaturesAsync(_cancellationTokenSource.Token));
            
            Console.WriteLine("Agent loops started, waiting for completion...");
            await Task.WhenAll(collectionTask, processingTask);
        }

        private async Task EnsureDatabaseAsync()
        {
            try
            {
                var factory = new DesignTimeDbContextFactory();
                using var context = factory.CreateDbContext(Array.Empty<string>());
                await context.Database.MigrateAsync();
                Console.WriteLine("Database migration completed");
                
                await EnsureTenantTopicAsync(context);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database migration failed: {ex.Message}");
            }
        }

        private async Task EnsureTenantTopicAsync(GuardianProtocolDbContext context)
        {
            try
            {
                var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .Build();
                
                var serviceBusConnectionString = configuration["ServiceBus:ConnectionString"] ?? "";
                
                // Create new context for tenant service to avoid disposal issues
                var factory = new DesignTimeDbContextFactory();
                using var tenantContext = factory.CreateDbContext(Array.Empty<string>());
                
                var tenantService = new TenantConfigurationService(tenantContext, serviceBusConnectionString);
                var tenantId = await tenantService.GetTenantIdAsync();
                await tenantService.EnsureTopicExistsAsync(tenantId);
                
                // Create a new tenant service instance for the feature engine
                var featureTenantContext = factory.CreateDbContext(Array.Empty<string>());
                var featureTenantService = new TenantConfigurationService(featureTenantContext, serviceBusConnectionString);
                _featureEngine.UpdateTenantService(featureTenantService);
                
                Console.WriteLine($"Tenant topic ensured for: {tenantId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Tenant topic creation failed: {ex.Message}");
            }
        }

        public void Stop()
        {
            _cancellationTokenSource.Cancel();
        }

        private async Task CollectSignalsAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine("Signal collection loop started");
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var allSignals = new List<SignalCapture>();
                    
                    foreach (var collector in _collectors)
                    {
                        try
                        {
                            var signals = await collector.CollectAsync();
                            allSignals.AddRange(signals);
                        }
                        catch (UnauthorizedAccessException)
                        {
                            // Skip collectors that require elevated permissions
                        }
                        catch (System.ComponentModel.Win32Exception)
                        {
                            // Skip collectors with process access issues
                        }
                        catch { /* Skip other collection errors */ }
                    }
                    
                    await WriteSignalsToLogAsync(allSignals);
                    
                    if (allSignals.Any())
                    {
                        var signalCounts = allSignals.GroupBy(s => s.Type).ToDictionary(g => g.Key, g => g.Count());
                        Console.WriteLine($"Collected signals: {string.Join(", ", signalCounts.Select(kv => $"{kv.Key}={kv.Value}"))}");
                    }
                    
                    await Task.Delay(5000, cancellationToken);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Console.WriteLine($"Signal collection error: {ex.Message}");
                    await Task.Delay(1000, cancellationToken);
                }
            }
        }

        private async Task ProcessFeaturesAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine("Feature processing loop started");
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await _featureEngine.ExtractFeaturesAsync();
                    await Task.Delay(10000, cancellationToken);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Console.WriteLine($"Feature processing error: {ex.Message}");
                    await Task.Delay(5000, cancellationToken);
                }
            }
        }

        private async Task WriteSignalsToLogAsync(List<SignalCapture> signals)
        {
            if (!signals.Any()) return;
            
            var signalEvents = signals.Select(s => new SignalEventLog
            {
                SignalType = s.Type.ToString(),
                Timestamp = s.Timestamp,
                Security = s.Security,
                HipaaViolation = s.HipaaViolation,
                ProcessName = s.ProcessName,
                IsConnected = s.IsConnected,
                KeyPressed = s.KeyPressed,
                Button = s.Button,
                ActiveProcessCount = s.ActiveProcessCount,
                CurrentApp = s.CurrentApp,
                BytesReceived = s.BytesReceived,
                BytesSent = s.BytesSent,
                VpnConnectionCount = s.VpnConnectionCount,
                EncryptionEnabled = s.EncryptionEnabled,
                EncryptionMethod = s.EncryptionMethod
            });

            var jsonLines = signalEvents.Select(s => JsonSerializer.Serialize(s));
            await File.AppendAllLinesAsync(_logFilePath, jsonLines);
        }
    }
}