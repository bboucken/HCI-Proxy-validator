# HCI-Proxy-validator

## Description

The purpose of this script is to check all Proxy configuration on Azure Stack HCI environment.<p>
Proxy configuration can be stored for WinHTTP and WinInet in registry, but also in variable environment, or, assigned by script of DNS/DHCP option (for WPAD).<p>
This script displays all places that might be relevant for proxy configuration.<p>
Depending on the service/application running on Azure Stack HCI, the proxy information can be retrieved from different places. See Offical Links bellow to have a deeper description on proxy configuration for each service/application installed on nodes.<p>

## Official links
[Azure Arc agent](https://learn.microsoft.com/en-us/azure/azure-arc/servers/manage-agent)<p>
[Azure Arc requirement](https://learn.microsoft.com/en-us/azure/azure-arc/servers/network-requirements?tabs=azure-cloud#urls)<p>
[Azure Stack HCI requirement](https://learn.microsoft.com/en-us/azure-stack/hci/concepts/firewall-requirements?tabs=allow-table)<p>
[Azure Monitoring agent](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/log-analytics-agent)<p>
[Microsoft Azure Recovery agent (MARS)](https://learn.microsoft.com/en-us/azure/backup/install-mars-agent)<p>
[Azure Storage for Witness Cloud](https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-firewall-and-proxy#proxy)<p>
  
## Pointers
[WinINet versus WinHTTP](https://learn.microsoft.com/en-us/windows/win32/wininet/wininet-vs-winhttp)<p>
[Under the Hood: WinInet](https://techcommunity.microsoft.com/t5/ask-the-performance-team/under-the-hood-wininet/ba-p/372499)<p>
[Under the Hood: WinHTTP](https://techcommunity.microsoft.com/t5/ask-the-performance-team/under-the-hood-winhttp/ba-p/372512)<p>

## ChangeLog:
v1.0
<ul><li>First version of script</li></ul><p>
v1.3
<ul><li>Enable network interface selection to run netsh trace and avoid using SMB related interfaces</li></ul><p>
v1.4
<ul><li>Add the -List switch to use a custom URI list for connectivity tests</li></ul><p>
v1.5
<ul><li>Scan HCI and AKS proxy settings</li></ul><p>
v1.6
<ul><li>Scan Azure Arc proxy settings</li></ul><p>
v1.7
<ul><li>Scan MARS proxy settings</li></ul><p>
v1.8
<ul><li>Add Get-NetRoute and DNS client cache information</li></ul><p>
v1.9
<ul><li>Fix MARS settings config</li></ul><p>

