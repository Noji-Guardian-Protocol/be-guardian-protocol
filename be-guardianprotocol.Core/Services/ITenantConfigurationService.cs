using System.Threading.Tasks;

namespace be_guardianprotocol.Core.Services
{
    public interface ITenantConfigurationService
    {
        Task<T> GetConfigurationAsync<T>(string tenantId, string configurationType);
        Task<string> GetServiceBusTopicAsync(string tenantId);
        Task EnsureTopicExistsAsync(string tenantId);
        Task<string> GetTenantIdAsync();
    }
}