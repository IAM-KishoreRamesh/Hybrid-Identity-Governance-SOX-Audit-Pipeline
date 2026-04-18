/*
  Azure Governance Lab Template
  Purpose: Deploys a secure Log Analytics environment with a Linux VM, 
           Data Collection Rules, RBAC, and Resource Locks for SOX compliance.
*/

// ==========================================
// PARAMETERS
// ==========================================

@description('Name of the Log Analytics workspace')
param workspaceName string = 'law-oimaudit-dev-centralindia'

@description('The approved Azure region for deployment to satisfy governance policy')
param location string = 'centralindia'

@description('Mandatory Governance tags for resource tracking and cost allocation')
param defaultTags object = {
  Environment: 'Dev'
  Project: 'OIMAudit'
}

@description('The Microsoft Entra (Azure AD) Object ID of the Auditor Group')
param auditorPrincipalId string = '1958d29f-f78d-4901-a5de-39ea434081cb'

@description('Name of the Data Collection Endpoint')
param dataCollectionEndpointName string = 'dce-oimaudit-dev-centralindia'

@description('Name of the Data Collection Rule')
param dataCollectionRuleName string = 'dcr-oimaudit-dev-centralindia'

@description('Username for the VM')
param adminUsername string = 'azureadmin'

@description('SSH Public Key for the VM')
param adminPublicKey string 

@description('Name of the VM to be deployed')
param vmName string = 'vm-oimaudit-dev-centralindia'

@description('Name of the Virtual Network')
param vnetName string = 'vnet-oimaudit-dev-centralindia'

// ==========================================
// VARIABLES
// ==========================================

var logAnalyticsContributorRoleId = '92aaf0da-9dab-42b6-94a3-d43ce8d16293' // Built-in: Log Analytics Contributor
var logAnalyticsReaderRoleId = '73c42c96-874c-492b-b04d-ab87d138a893'      // Built-in: Log Analytics Reader
var managedIdentityName = 'id-oimaudit-dev-centralindia'
var subnetName = 'snet-oimaudit-dev-centralindia'

// ==========================================
// IDENTITY RESOURCES
// ==========================================

@description('User Assigned Managed Identity used by the Azure Monitor Agent for secure, credential-less log ingestion')
resource logIngestionIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: managedIdentityName
  location: location
  tags: defaultTags
}

// ==========================================
// NETWORKING RESOURCES
// ==========================================

@description('Virtual Network for the audit lab environment')
resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  tags: defaultTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
    ]
  }
}

@description('Public IP for administrative SSH access to the dummy VM')
resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: 'pip-oimaudit-dev-centralindia'
  location: location
  tags: defaultTags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'  // Standard SKU requires static allocation
  }
}

@description('NSG to restrict traffic; only SSH (Port 22) is allowed for management')
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'nsg-oimaudit-dev-centralindia'
  location: location
  tags: defaultTags
  properties: {
    securityRules: [
      {
        name: 'allow-ssh'
        properties: {
          priority: 100
          protocol: 'Tcp'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
          access: 'Allow'
        }
      }
    ]
  }
}

@description('Network Interface connecting the VM to the Virtual Network')
resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: 'nic-oimaudit-dev-centralindia'
  location: location
  tags: defaultTags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig-oimaudit-dev'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: vnet.properties.subnets[0].id
          }
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsg.id
    }
  }
}

// ==========================================
// COMPUTE RESOURCES
// ==========================================

@description('Dummy Ubuntu VM acting as the source for syslog data to test governance policies')
resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: vmName
  location: location
  tags: defaultTags
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: 'dummyvm'
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: adminPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

// ==========================================
// MONITORING INFRASTRUCTURE
// ==========================================

@description('Central Log Analytics Workspace for storing SOX audit telemetry')
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2020-08-01' = {
  name: workspaceName
  location: location
  tags: defaultTags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

@description('The Regional Endpoint that the Azure Monitor Agent (AMA) uses to send logs')
resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = {
  name: dataCollectionEndpointName
  location: location
  tags: defaultTags
  properties:{
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

@description('Standardized Data Collection Rule (DCR) to enforce syslog collection across the environment')
resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: dataCollectionRuleName
  location: location
  tags: defaultTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${logIngestionIdentity.id}': {}
    }
  }
  properties: {
    dataCollectionEndpointId: dataCollectionEndpoint.id
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspace.id
          name: 'law-destination'
        }
      ]
    }
    dataSources: {
      syslog: [
        {
          name: 'dummyLinuxSyslog'
          facilityNames: [
            'syslog'
          ]
          logLevels: [
            '*'
          ]
          streams: [
            'Microsoft-Syslog' 
          ]
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-Syslog'
        ]
        destinations: [
          'law-destination'
        ]
      }
    ]
  }
}

// ==========================================
// ACCESS CONTROL (RBAC)
// ==========================================

@description('RBAC: Grant the Managed Identity permission to push logs into the workspace (Least Privilege)')
resource identityRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logAnalyticsWorkspace.id, logIngestionIdentity.id, logAnalyticsContributorRoleId)
  scope: logAnalyticsWorkspace
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', logAnalyticsContributorRoleId)
    principalId: logIngestionIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

@description('RBAC: Grant the External Auditor group read-only access for compliance verification')
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logAnalyticsWorkspace.id, auditorPrincipalId, logAnalyticsReaderRoleId)
  scope: logAnalyticsWorkspace
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', logAnalyticsReaderRoleId)
    principalId: auditorPrincipalId
    principalType: 'Group'
  }
}

// ==========================================
// GOVERNANCE & PROTECTION
// ==========================================

@description('Governance: Resource Lock to prevent accidental deletion of audit data, ensuring SOX data retention compliance')
resource workspaceLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: '${workspaceName}-SOX-Retention-Lock'
  scope: logAnalyticsWorkspace
  properties: {
    level: 'CanNotDelete'
    notes: 'Mandatory for SOX Compliance. Prevents deletion of the primary audit log repository.'
  }
}
