using System;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Azure.Messaging.ServiceBus.Administration;
using be_guardianprotocol.Core.Data;
using be_guardianprotocol.Core.Models;

namespace be_guardianprotocol.Core.Services
{
    public class TenantConfigurationService : ITenantConfigurationService
    {
        private readonly GuardianProtocolDbContext _context;
        private readonly string _serviceBusConnectionString;

        public TenantConfigurationService(GuardianProtocolDbContext context, string serviceBusConnectionString)
        {
            _context = context;
            _serviceBusConnectionString = serviceBusConnectionString;
        }

        public async Task<string> GetTenantIdAsync()
        {
            try
            {
                var domain = Environment.UserDomainName;
                return domain.ToLower().Replace(".", "-");
            }
            catch
            {
                return "default-tenant";
            }
        }

        public async Task<T> GetConfigurationAsync<T>(string tenantId, string configurationType)
        {
            var config = await _context.TenantConfigurations
                .FirstOrDefaultAsync(t => t.TenantId == tenantId && t.ConfigurationType == configurationType);

            if (config == null || string.IsNullOrEmpty(config.ConfigurationData))
                return default(T);

            return JsonSerializer.Deserialize<T>(config.ConfigurationData);
        }

        public async Task<string> GetServiceBusTopicAsync(string tenantId)
        {
            var topic = await _context.TenantTopics
                .FirstOrDefaultAsync(t => t.TenantId == tenantId);

            return topic?.TopicName ?? $"guardian-{tenantId.ToLower()}";
        }

        public async Task EnsureTopicExistsAsync(string tenantId)
        {
            try
            {
                var topicName = await GetServiceBusTopicAsync(tenantId);
                var adminClient = new ServiceBusAdministrationClient(_serviceBusConnectionString);

                if (!await adminClient.TopicExistsAsync(topicName))
                {
                    await adminClient.CreateTopicAsync(topicName);
                    await SaveTopicAsync(tenantId, topicName);
                }
                
                // Ensure subscription exists
                var subscriptionName = $"{topicName}-subscription";
                if (!await adminClient.SubscriptionExistsAsync(topicName, subscriptionName))
                {
                    await adminClient.CreateSubscriptionAsync(topicName, subscriptionName);
                }
            }
            catch
            {
                // Topic creation handled during tenant setup
            }
        }

        private async Task SaveTopicAsync(string tenantId, string topicName)
        {
            var tenantTopic = new TenantTopic
            {
                TenantId = tenantId,
                TopicName = topicName,
                ConnectionString = _serviceBusConnectionString
            };

            _context.TenantTopics.Add(tenantTopic);
            await _context.SaveChangesAsync();
        }
    }
}