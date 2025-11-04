using System;
using System.Collections.Generic;

namespace be_guardianprotocol.Core.Models
{
    public class TenantConfiguration
    {
        public string TenantId { get; set; } = "";
        public string ConfigurationType { get; set; } = "";
        public string ConfigurationData { get; set; } = "";
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    }

    public class TenantTopic
    {
        public string TenantId { get; set; } = "";
        public string TopicName { get; set; } = "";
        public string ConnectionString { get; set; } = "";
        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
    }

    public class ApprovedApplicationsConfig
    {
        public List<string> ApprovedApplications { get; set; } = new();
        public List<string> ApprovedPublishers { get; set; } = new();
        public List<string> SuspiciousDirectories { get; set; } = new();
    }

    public class AuthorizedSSIDsConfig
    {
        public List<string> AuthorizedSSIDs { get; set; } = new();
    }

    public class EndpointProtectionConfig
    {
        public List<string> SecurityServices { get; set; } = new();
        public List<string> SecurityProcesses { get; set; } = new();
        public List<string> ProcessNameExclusions { get; set; } = new();
    }

    public class USBSecurityConfig
    {
        public List<AuthorizedDevice> AuthorizedDevices { get; set; } = new();
    }

    public class AuthorizedDevice
    {
        public string VendorID { get; set; } = "";
        public string ProductID { get; set; } = "";
        public string Description { get; set; } = "";
    }
}