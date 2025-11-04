using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace be_guardianprotocol.Core.Services
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddGuardianProtocol(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddSingleton<FeatureExtractionEngine>();
            
            var serviceBusConfig = configuration.GetSection("ServiceBus");
            var connectionString = serviceBusConfig["ConnectionString"];
            var topicName = serviceBusConfig["TopicName"];
            
            if (!string.IsNullOrEmpty(connectionString) && !string.IsNullOrEmpty(topicName))
            {
                services.AddSingleton(provider => 
                    new ServiceBusPublisher(
                        connectionString, 
                        topicName, 
                        provider.GetRequiredService<FeatureExtractionEngine>(),
                        provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<ServiceBusPublisher>>()
                    )
                );
                services.AddHostedService<ServiceBusPublisher>(provider => provider.GetRequiredService<ServiceBusPublisher>());
            }
            
            return services;
        }
    }
}