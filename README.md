Create Availability Group Listener in Hybrid IT
===============================================

            
**NOTE: AlwaysOn Availability Groups in Windows Azure currently only supports listener creation in Window Server 2012 VMs.**

This script configures an availability group listener for an availability group that is running in hybrid IT (Windows Azure with site-to-site VPN with an on-premise network). This script is to be run on your local client from within a Windows Azure PowerShell
 window with administrative privileges. It automatically configures the Windows Azure settings and also configures all on-premise servers and each Windows Azure VM remotely using PowerShell remoting.

**ACTION SUMMARY**

  *  Validate the specified parameters 
  *  Validate your configuration 
  *  Create public load-balanced endpoints for the VMs with Direct Server Return (DSR) enabled

  *  Manually configure a client access point in the cluster 
  *  Configure the listener port in SQL Server 

**PREREQUISITES**


**NOTE: **If your VMs do not satisfy the prerequisites here, see alternative PowerShell methods at [http://blogs.msdn.com/b/sqlalwayson/archive/2013/08/06/availability-group-listener-in-windows-azure-now-supported-and-scripts-for-cloud-only-configuration.aspx](http://blogs.msdn.com/b/sqlalwayson/archive/2013/08/06/availability-group-listener-in-windows-azure-now-supported-and-scripts-for-cloud-only-configuration.aspx).


  *  Windows Azure PowerShell June 2013 or later installed on the local client. Download at
[http://go.microsoft.com/?linkid=9811175&clcid=0x409](http://go.microsoft.com/?linkid=9811175&clcid=0x409).

  *  You have imported your Windows Azure subscription into your Windows Azure PowerShell session. To do this, run 'Get-AzurePublishSettingsFile' to download a management certificate to a local directory, and then run 'Import-AzurePublishSettingsFile -PublishSettingsFile
 <filepath>'. 
  *  All cluster nodes in Windows Azure must belong to the same cloud service. 
  *  All cluster nodes must be running Windows Server 2012 with KB2854082 installed.

  *  All availability group nodes on-premise are in the same subnet. 
  *  All availability group nodes in Windows Azure are in the same subnet. 
  *  The user specified in the -DomainAccount parameter must have the following permissions on the cluster nodes:

  *  local administrator 
  *  SQL Server sysadmin role 
  *  Full control of the cluster  

**BASIC SYNTAX**

If running PowerShell remote management for the first time, use the -InstallWinRMCert parameter:

To specify the name of the Azure endpoint ('ListenerEndpoint' by default):














        
    
TechNet gallery is retiring! This script was migrated from TechNet script center to GitHub by Microsoft Azure Automation product group. All the Script Center fields like Rating, RatingCount and DownloadCount have been carried over to Github as-is for the migrated scripts only. Note : The Script Center fields will not be applicable for the new repositories created in Github & hence those fields will not show up for new Github repositories.
