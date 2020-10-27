<#
 * Copyright Microsoft Corporation
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
#>

##########################################################################################################
#
# Description:
#     This script configures an availability group listener for an availability group that is running
#     in Windows Azure VMs. This script is to be run on your local client from within a Windows Azure 
#     PowerShell window with administrative privileges. It automatically configures the Windows Azure 
#     settings and also configures each VM remotely using PowerShell remoting.
#
# Prerequisites:
#     * Windows Azure PowerShell June 2013 or later installed on the local client. Download at 
#       http://go.microsoft.com/?linkid=9811175&clcid=0x409.
#     * You have imported your Windows Azure subscription into your Windows Azure PowerShell session. To
#       do this, run "Get-AzurePublishSettingsFile" to download a management certificate to a local
#       directory, and then run "Import-AzurePublishSettingsFile -PublishSettingsFile <filepath>".
#     * All cluster VMs must belong to the same cloud service.
#     * All cluster VMs must be running Windows Server 2012 with KB2854082 installed.
#     * All availability group nodes are running in Windows Azure and in the same subnet.
#     * The user specified in the -DomainAccount parameter must have the following permissions on the 
#       cluster VMs:
#           - local administrator
#           - SQL Server sysadmin role
#           - Full control of the cluster
#
# Syntax:
#
#     .\ConfigureAGListenerCloudOnly.ps1  -AGName "MyAG" -ListenerName "MyListener" -ServiceName "MySvc" `
#           -ListenerIPOnPrem "123.456.789.10" -WSFCAzure "Node3","Node4"... -WSFCOnPrem "Node1","Node2"... 
#           -DomainAccount "DOMAIN\username" -Password "MyPassword" 
#
#     If running PowerShell remote management for the first time, use the -InstallWinRMCert parameter:
#     .\ConfigureAGListenerCloudOnly.ps1  -AGName "MyAG" -ListenerName "MyListener" -ServiceName "MySvc" `
#           -ListenerIPOnPrem "123.456.789.10" -WSFCAzure "Node3","Node4"... -WSFCOnPrem "Node1","Node2"... `
#           -DomainAccount "DOMAIN\username" -Password "MyPassword" -InstallWinRMCert
#
#     To specify the name of the Azure endpoint ("ListenerEndpoint" by default):
#     .\ConfigureAGListenerCloudOnly.ps1  -AGName "MyAG" -ListenerName "MyListener" -ServiceName "MySvc" `
#           -EndpointName "MyEndpointName" -ListenerIPOnPrem "123.456.789.10" -WSFCAzure "Node3","Node4"...  `
#           -WSFCOnPrem "Node1","Node2"... -DomainAccount "DOMAIN\username" -Password "MyPassword" 
#
#     To specify the public port of the Azure endpoint ("1433" by default):
#     .\ConfigureAGListenerCloudOnly.ps1  -AGName "MyAG" -ListenerName "MyListener" -ServiceName "MySvc" `
#           -EndpointPort "10000" -ListenerIPOnPrem "123.456.789.10" -WSFCAzure "Node3","Node4"...  `
#           -WSFCOnPrem "Node1","Node2"... -DomainAccount "DOMAIN\username" -Password "MyPassword" 
#
# Summary of the script:
#     1. Validate the specified parameters
#     2. Validate your configuration
#     3. Create public load-balanced endpoints for the VMs with Direct Server Return (DSR) enabled 
#     4. Manually configure a client access point in the cluster
#     5. Configure the listener port in SQL Server
#
#
##########################################################################################################
param(
   [Parameter(Mandatory=$true)]
    [string]$AGName,
   [Parameter(Mandatory=$true)]
    [string]$ListenerName,
   [Parameter(Mandatory=$true)]
    [string]$ServiceName,
   [Parameter(Mandatory=$true)]
    [string]$ListenerIPOnPrem,
   [Parameter(Mandatory=$false)]
    [string]$EndpointName = "ListenerEndpoint",
   [Parameter(Mandatory=$false)]
    [int]$EndpointPort = 1433,
   [Parameter(Mandatory=$true)]
    [array]$WSFCAzure,
   [Parameter(Mandatory=$true)]
    [array]$WSFCOnPrem,
   [Parameter(Mandatory=$true)]
    [string]$DomainAccount,
   [Parameter(Mandatory=$true)]
    [string]$Password
)

function RunWSManScriptBlock (
$computerName,
$userName,
$password,
$azureVM = $false,
$credSSP = $false,
$argumentList,
$scriptBlock
)
{
    $command = 'Invoke-Command '
    $command += '-ComputerName $computerName '
    $command += '-Credential (New-Object System.Management.Automation.PSCredential($userName, $(ConvertTo-SecureString $password -AsPlainText -Force))) '
    $command += '-ArgumentList $argumentList '
    $command += '-ScriptBlock $scriptBlock '
    $command += '-ErrorAction Stop '

    If ($azureVM)
    {
        $command += '-SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck) '
        $command += '-UseSSL '
    }
    If($credSSP)
    {
        $command += '-EnableNetworkAccess '
        $command += '-Authentication Credssp '
    }

    Return (Invoke-Expression $command)
}

# Validate if we are running in a Windows Azure PowerShell session
If ((Get-Module | where {$_.Name -eq "Azure"}) -eq $null)
{
    Write-Error "You are not running this script in a Windows Azure PowerShell session - ABORT"
    Exit 1
}

# Validate if there is a valid Windows Azure subscription
$subscription = Get-AzureSubscription -Current
If ($subscription -eq $null)
{
    Write-Error "No Windows Azure subscription is found - ABORT"
    Exit 1
}
Write-Host "Current Windows Azure subscription:" $subscription.SubscriptionName

# Validate if the cloud service is valid
If((Get-AzureService -ServiceName $ServiceName) -eq $null)
{
    Write-Error "Cloud service $ServiceName is not found - ABORT"
    Exit 1
}
$serviceip = (Resolve-DnsName -Name "$ServiceName.cloudapp.net").IPAddress

# Validate if IP address specified in $ListenerIPOnPrem is a valid IPv4 address
If(-not [IPAddress]::TryParse($ListenerIPOnPrem, [ref]$null))
{
    Write-Error "$ListenerIPOnPrem is not a valid IPv4 address - ABORT"
    Exit 1
}
If(([IPAddress]$ListenerIPOnPrem).AddressFamily -ne "InterNetwork")
{
    Write-Error "$ListenerIPOnPrem is not a valid IPv4 address - ABORT"
    Exit 1
}

# Validate if VMs specified in $WSFCAzure is in the cloud service 
If((Compare-Object (Get-AzureVM -ServiceName $ServiceName).Name $WSFCAzure | where {$_.SideIndicator -eq "=>"}) -ne $null)
{
    Write-Error "Not all specified VMs belong to the cloud service $ServiceName - ABORT"
    Exit 1
}
$clustervms = (Get-AzureVM -ServiceName $ServiceName) | where {$WSFCAzure -contains $_.Name}

Write-Host "Validating endpoint..."

# Verify that no endpoint with port $EndpointPort exists
If (($clustervms | Get-AzureEndpoint | where {$_.Port -eq $EndpointPort}) -ne $null )
{
    Write-Error "Endpoints using the public port $EndpointPort already exists. Remove the endpoint with public port $EndpointPort from all VMs in the cloud service before proceeding - ABORT"
    Exit 1
}

# Verify that no endpoint with the specified name exists
If (($clustervms | Get-AzureEndpoint -Name $EndpointName) -ne $null)
{
    Write-Error "The load-balanced endpoint name you specified for cloud service $ServiceName is already used by one or more VMs in the cloud service. Specify a different endpoint name when you run the script - ABORT"
    Exit 1
}

$ret = $null
$firstIteration = $true

ForEach ($node in ($WSFCAzure + $WSFCOnPrem))
{
    $out = RunWSManScriptBlock `
            -computerName $node `
            -userName $DomainAccount `
            -password $Password `
            -azureVM ($WSFCAzure -contains $node) `
            -credSSP $false `
            -argumentList $AGName, ($WSFCAzure + $WSFCOnPrem), $ListenerName, $ListenerIPOnPrem, $firstIteration `
            -scriptBlock `
            {
                param($AGName, $WSFCNodes, $AGListener, $IPOnPrem, $FirstIteration)

                if ([System.Environment]::OSVersion.Version.Build -lt 9200)
                {
                    Write-Error "This script is not supported on Windows Server 2008 R2 or lower." 
                    Return $null
                }

                # Verify if failover clustering is installed
                If (-not (Get-WindowsFeature -Name Failover-Clustering).Installed)
                {
                    Write-Error "Failover Clustering is not installed on $env:COMPUTERNAME."
                    Return $null
                }
                # Make sure that the PowerShell cmdlets are installed
                Add-WindowsFeature "RSAT-Clustering-PowerShell" | Out-Null

                # Verify that KB2854082 is installed on each cluster node for Windows Server 2012 only
                If (([System.Environment]::OSVersion.Version.Minor -eq 2) -and ((Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName . -Property HotFixId -filter "HotFixID = 'KB2854082'") -eq $null))
                {
                    Write-Error "Required hotfix KB2854082 is NOT installed on $env:COMPUTERNAME. Install the hotfix on all cluster node VMs before running this script."
                    Return $null
                }

                $agnodes = $null

                # This if clause is run only once
                If ($FirstIteration)
                {
                    Write-Host "Validating cluster parameters..."

                    Import-Module FailoverClusters

                    # Verify that computer is part of a cluster
                    If ((Get-ClusterNode $env:COMPUTERNAME -ErrorAction SilentlyContinue) -eq $null)
                    {
                        Write-Error "$env:COMPUTERNAME is not part of a cluster."
                        Return $null
                    }
                    
                    # Verify that all nodes are part of the same cluster
                    If ((Compare-Object $WSFCNodes (Get-ClusterNode).Name) -ne $null) 
                    {
                        Write-Error "The specified cluster node names do not match the cluster nodes configured in your cluster. If -AGNodes does not include all cluster node VMs, you should specify all cluster node VMs in -WSFCAzure."
                        Return $null
                    }
                    # Verify that there are only two subnets
                    If ((Get-ClusterNetwork).Count -ne 2) 
                    {
                        Write-Error "More than two cluster networks are detected. This script only supports two subnets (one on-premise and one in Windows Azure)."
                        Return $null
                    }

                    $ag = Get-ClusterGroup $AGName -ErrorAction SilentlyContinue
                    # Verify the availability group name
                    If ($ag -eq $null)
                    {
                        Write-Error "No availability group resource group by the name of $AGName is found in the cluster."
                        Return $null
                    }
                    # Verify the health of the cluster and availability group, and output any data that indicates less than optimal health
                    If ($ag.State -ne "Online" -or `
                        (Get-ClusterNode | where {$_.State -ne "Up"}) -ne $null -or `
                        (Get-ClusterNetwork | where {$_.State -ne "Up"}) -ne $null -or `
                        ((Get-ClusterQuorum).QuorumResource -ne $null -and (Get-ClusterQuorum).QuorumResource.State -ne "Online"))
                    {
                        Write-Error "The cluster or the availability group is not in optimal health. Restore the cluster and the availability group to optimal health before proceeding. If you have configured a non-working availability group listener, delete both the network name and the IP address."
                        $ag | where {$_.State -ne "Online"} | Out-String -Stream | Write-Host -ForegroundColor Red
                        Get-ClusterNode | where {$_.State -ne "Up"} | Out-String -Stream | Write-Host -ForegroundColor Red
                        Get-ClusterNetwork | where {$_.State -ne "Up"} | Out-String -Stream | Write-Host -ForegroundColor Red
                        (Get-ClusterQuorum).QuorumResource | Out-String -Stream | Write-Host -ForegroundColor Red
                        Return $null
                    }
                    # If the specified listener name is already in use, prompt the user for a different name
                    While (($ag | Get-ClusterResource | where {$_.ResourceType -eq "Network Name" -and $_.Name -eq $AGListener}) -ne $null) 
                    {
                        If ((Read-Host "The availability group $AGName already has a network name called $AGListener. Do you want to specify a different name for the new availability group listener? [Y/N]") -eq "Y")
                        {
                            $AGListener = Read-Host "AG Listener Name: "
                        }
                        Else
                        {
                            Write-Error "The availability group $AGName already has a network name called $AGListener."
                            Return $null
                        }
                    }

                    # Retrieve the cluster network for the on-premise subnet. Information on this cluster network, such as name and subnet mask, are used later during listener creation
                    $onpremNetwork = (Get-ClusterNetwork | where {(([IPAddress]$IPOnPrem).Address -band ([IPAddress]($_.AddressMask)).Address) -eq ([IPAddress]($_.Address)).Address})
                    If ($onpremNetwork -eq $null)
                    {
                        Write-Error "The IP address $IPOnPrem is not a valid IP address in any of the cluster netoworks."
                        Return $null
                    }

                    Write-Host "Cluster validation - SUCCESS"

                    Import-Module 'sqlps' -ErrorAction Stop | Out-Host
                    # Retrieve the availability group nodes
                    $agnodes = (Invoke-Sqlcmd -Query "select node_name from sys.dm_hadr_availability_replica_cluster_nodes").node_name
                    # Retrieve the primary replica node
                    $primary = (Get-ClusterGroup $AGName).OwnerNode
                }

                Write-Host "Validation on $env:COMPUTERNAME - SUCCESS"

                If ($FirstIteration)
                { Return @($agnodes, $AGListener, $onpremNetwork, $primary) }
                Else
                { Return 0 }
            }

    If ($out -eq $null)
    {
        Write-Error "An error occurred while validating one of the cluster nodes - ABORT "
        Exit 1
    }
    If ($firstIteration)
    {
        $firstIteration = $false
        $agnodes = $out[0]
        $ListenerName = $out[1]
        $onpremnetwork = $out[2]
        $primary = $out[3]
    }

}

If($WSFCOnPrem -notcontains $primary)
{
    Write-Error "The current primary replica is not hosted on an on-premise server. - ABORT "
    Exit 1
}

Write-Host "------------------------------------------------"
Write-Host "Configuring availbility group endpoint..."

ForEach ($node in ($AGNodes | where {$WSFCAzure -contains $_}))
{
    Write-Host "Configuring $node..."

    # Create public endpoint on each availability group node
    Write-Host " Creating a load-balanced endpoint with DSR enabled..."
    Get-AzureVM -ServiceName $ServiceName -Name $node -ErrorAction Stop | 
        Add-AzureEndpoint `
            -Name $EndpointName `
            -Protocol "TCP" `
            -PublicPort $EndpointPort `
            -LocalPort $EndpointPort `
            -LBSetName "$EndpointName-LB" `
            -ProbePort 59999 `
            -ProbeProtocol "TCP" `
            -DirectServerReturn $true `
            -ErrorAction Stop | 
                Update-AzureVM -ErrorAction Stop

    RunWSManScriptBlock `
            -computerName $node `
            -userName $DomainAccount `
            -password $Password `
            -azureVM $true `
            -argumentList $EndpointPort `
            -scriptBlock `
    {
        param($listenerPort)
        # Open the probe port to be polled by the public endpoint
        Write-Host " Opening firewall port 59999 as the probe port"
        netsh advfirewall firewall add rule name='Load Balance Probe (TCP-In)' localport=59999 dir=in action=allow protocol=TCP | Out-Null
        Write-Host " Opening firewall port $listenerPort as the listener port"
        netsh advfirewall firewall add rule name='Availability Group Listener (TCP-In)' localport=$listenerPort dir=in action=allow protocol=TCP | Out-Null
    }

    Write-Host " Done configuring $node"
}

Write-Host "Configuring listener on $primary..."

RunWSManScriptBlock `
        -computerName $primary `
        -userName $DomainAccount `
        -password $Password `
        -azureVM $false `
        -argumentList $AGName, $ListenerName, $EndpointPort, $serviceip, $ListenerIPOnPrem, $onpremNetwork `
        -scriptBlock `
{
    param($AGName, $ListenerName, $ListenerPort, $IPAddress, $IPOnPrem, $NetworkOnPrem)

    # Configure the availability group endpoint on the primary replica server
    If ((Get-ClusterGroup $AGName).OwnerNode -eq $env:COMPUTERNAME)
    {
        Write-Host " $env:COMPUTERNAME is the current primary replica server. Beginning configuration of availability group listener for $AGName on $env:COMPUTERNAME."
        Write-Host " Creating IP addresses"
        Add-ClusterResource "IP Address $IPOnPrem" -ResourceType "IP Address" -Group $AGName -ErrorAction Stop |  Set-ClusterParameter -Multiple @{"Address"="$IPOnPrem";SubnetMask=$NetworkOnPrem.AddressMask;"Network"=$NetworkOnPrem.Name;"EnableDhcp"=0} -ErrorAction Stop
        Add-ClusterResource "IP Address $IPAddress" -ResourceType "IP Address" -Group $AGName -ErrorAction Stop |  Set-ClusterParameter -Multiple @{"Address"="$IPAddress";"ProbePort"="59999";SubnetMask="255.255.255.255";"Network"=((Get-ClusterNetwork).Name | where {$_ -ne $NetworkOnPrem.Name});"OverrideAddressMatch"=1;"EnableDhcp"=0} -ErrorAction Stop
        Write-Host " Creating network name for the listener"
        Add-ClusterResource -Name $ListenerName -ResourceType "Network Name" -Group $AGName -ErrorAction Stop | Set-ClusterParameter -Multiple @{"Name"=$ListenerName;"DnsName"=$ListenerName} -ErrorAction Stop
        Write-Host " Setting the network name's dependency on the IP addresses"
        Get-ClusterGroup $AGName | Get-ClusterResource | where {$_.Name -eq $ListenerName} | Set-ClusterResourceDependency "[IP Address $IPOnPrem] or [IP Address $IPAddress]" -ErrorAction Stop
        Write-Host " Starting the network name"
        Start-ClusterResource -Name $ListenerName -ErrorAction Stop | Out-Null
        Write-Host " Setting the availability group resource group's dependency on the network name"
        Get-ClusterResource -Name $AGName | Set-ClusterResourceDependency "[$ListenerName]" -ErrorAction Stop
        Write-Host " Setting the listener port to $ListenerPort. Note that if you configure a non-1433 port, then client applications must specify the port number when connecting to the listener."
        Set-SqlAvailabilityGroupListener -Path SQLSERVER:\SQL\$env:COMPUTERNAME\DEFAULT\AvailabilityGroups\$AGName\AvailabilityGroupListeners\$ListenerName -Port $ListenerPort -ErrorAction Stop | Out-Null
    }
    Else
    {
        Write-Error "$env:COMPUTERNAME does not host the primary replica currently."
    }
}

Write-Host " Done configuring $node"

Write-Host ""
Write-Host "Done configuring listener $ListenerName for availability group $AGName. To test connection to the listener, use a domain-joined VM that is not in the same cloud service (DSR not supported from within the same cloud service). Use a longer login timeout since network messages are traversing the VM’s public endpoint. You can use sqlcmd or SSMS. For example:"
Write-Host "sqlcmd -S $ListenerName -d <DATABASENAME> -Q 'select @@servername, db_name()' -l 15"
Write-Host "Once you successfully connect to the listener. Fail over the AG and test the listener connection again using the same client. The query above should return a different server name."
