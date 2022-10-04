# HCI-Proxy-validator

## Description

The purpose of this script is to check all Proxy configuration on Azure Stack HCI environment.
Proxy configuration can be stored for WinHTTP and WinInet in registry, but also in variable environment

## Pointers
[WinINet versus WinHTTP](https://learn.microsoft.com/en-us/windows/win32/wininet/wininet-vs-winhttp)<p>
[Under the Hood: WinInet](https://techcommunity.microsoft.com/t5/ask-the-performance-team/under-the-hood-wininet/ba-p/372499)<p>
[Under the Hood: WinHTTP](https://techcommunity.microsoft.com/t5/ask-the-performance-team/under-the-hood-winhttp/ba-p/372512)<p>
[Azure Arc agent](https://learn.microsoft.com/en-us/azure/azure-arc/servers/manage-agent)<p>
[Azure Arc requirement](https://learn.microsoft.com/en-us/azure/azure-arc/servers/network-requirements?tabs=azure-cloud#urls)<p>
[Azure Stack HCI requirement](https://learn.microsoft.com/en-us/azure-stack/hci/concepts/firewall-requirements?tabs=allow-table)<p>
[Azure Monitoring agent](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/log-analytics-agent)<p>
[Microsoft Azure Recovery agent (MARS)](https://learn.microsoft.com/en-us/azure/backup/install-mars-agent)<p>
[Azure Storage for Witness Cloud](https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-firewall-and-proxy#proxy)<p>

## ChangeLog:
v1.0
-First version of script
v1.3
-Enable network interface selection to run netsh trace and avoid using SMB related interfaces
v1.4
-Add the -List switch to use a custom URI list for connectivity tests
v1.5
-Scan HCI and AKS proxy settings
v1.6
-Scan Azure Arc proxy settings
v1.7:
-Scan MARS proxy settings
v1.8:
- Add Get-NetRoute and DNS client cache information
v1.9:
- Fix MARS settings config 

