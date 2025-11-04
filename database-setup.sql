-- Guardian Protocol Multi-Tenant Database Setup

-- Tenant configurations table
CREATE TABLE TenantConfigurations (
    TenantId NVARCHAR(100) NOT NULL,
    ConfigurationType NVARCHAR(50) NOT NULL,
    ConfigurationData NVARCHAR(MAX) NOT NULL,
    LastUpdated DATETIME2 DEFAULT GETUTCDATE(),
    PRIMARY KEY (TenantId, ConfigurationType)
);

-- Service Bus topics table
CREATE TABLE TenantTopics (
    TenantId NVARCHAR(100) PRIMARY KEY,
    TopicName NVARCHAR(200) NOT NULL,
    ConnectionString NVARCHAR(500) NOT NULL,
    CreatedDate DATETIME2 DEFAULT GETUTCDATE()
);

-- Sample tenant configuration data
INSERT INTO TenantConfigurations (TenantId, ConfigurationType, ConfigurationData) VALUES
('acme-corp', 'ApprovedApplications', '{
  "ApprovedApplications": ["notepad.exe", "chrome.exe", "outlook.exe"],
  "ApprovedPublishers": ["Microsoft Corporation", "Google LLC"],
  "SuspiciousDirectories": ["Downloads", "Temp", "Desktop"]
}'),
('acme-corp', 'AuthorizedSSIDs', '{
  "AuthorizedSSIDs": ["ACME-CORPORATE", "ACME-GUEST"]
}'),
('acme-corp', 'EndpointProtection', '{
  "SecurityServices": ["WinDefend", "MsMpSvc"],
  "SecurityProcesses": ["MsMpEng", "NisSrv"],
  "ProcessNameExclusions": ["svchost", "services"]
}'),
('acme-corp', 'USBSecurity', '{
  "AuthorizedDevices": [
    {"VendorID": "0781", "ProductID": "5567", "Description": "ACME Corporate USB"}
  ]
}');

-- Sample topic registration
INSERT INTO TenantTopics (TenantId, TopicName, ConnectionString) VALUES
('acme-corp', 'guardian-acme-corp', 'Endpoint=sb://guardian-pro.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=1Xqhd83VxqoPke8xNGBEvxoeb0ZWdS7n2+ASbJ8yCJg=');