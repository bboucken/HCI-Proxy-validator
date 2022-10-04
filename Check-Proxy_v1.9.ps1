<# 
	.SYNOPSIS 
		Scan proxy configuration on Azure Stack HCI environment.

	.DESCRIPTION 
		Allow to check for all componenets that can be installed on Azure Stack HCI environment what are the specific proxy settings. 
        Can also test some resources on Internet to check if Proxy is currently configured.
        At least enable netsh tracing to perform investigations.
 
	.PARAMETER trace
		Specify to collect netsh trace during the test. Tihs also onboard InternetClient_dbg tracing for WinHTTP.
 
	.PARAMETER test
		Specify if during the script execution the Internet connectivity is effective.
        Combined to -List you can test all resources you provided a link into an CSV file.
        The default URI will be used if not -List provided:
            "login.microsoftonline.com"
            "graph.windows.net"
            "management.azure.com"
            "azurestackhci.azurefd.net"
            "login.microsoftonline.com"
            "edgesupprdwestuufrontend.westus2.cloudapp.azure.com"
            "edgesupprdwesteufrontend.westeurope.cloudapp.azure.com"
            "edgesupprdeastusfrontend.eastus.cloudapp.azure.com"
            "edgesupprdwestcufrontend.westcentralus.cloudapp.azure.com"
            "edgesupprdasiasefrontend.southeastasia.cloudapp.azure.com"
            "edgesupprd.trafficmanager.net";"www.powershellgallery.com/packages/Az.StackHCI"
            "windowsupdate.microsoft.com";"update.microsoft.com";"windowsupdate.com"
            "download.windowsupdate.com";"download.microsoft.com";"wustat.windows.com"
            "ntservicepack.microsoft.com"
            "go.microsoft.com"
            "dl.delivery.mp.microsoft.com"
            "dl.delivery.mp.microsoft.com"
 
	.PARAMETER hci
		Specify to use the Test-AzStackHCIConnection script sample to check connectiity health for Azure Stack HCI.

	# .PARAMETER aks
		Specify to retrieve the AKS proxy configuration if set.

	.PARAMETER arc
		Specify to retrieve the Azure Arc proxy configuration if set.

	.PARAMETER mars 
		Specify to retrieve the Microsot Azure Recovery Service proxy configuration if set.

	.PARAMETER all  
		Specify to run proxy check for Azure Stack HCI, Azure Arc, AKS on HCI, Microsoft Azure Recovery Service.
        Should be use to prevent adding manually switches -hci -arc -mars -aks
 
	.PARAMETER list 
		Define the CSV file that contains all the internal and external resource that can be run during connectivity test.
        This superseeds the default test list imbedeed in this script.
        This implies the switch -test selected.
 
	.EXAMPLE 
		PS C:\>.\Check-Proxy.ps1 -trace -test -hci -aks -arc -mars
        This will collect netsh trace, run test of the default URI and retrieve proxy info for HCI, AKS, ARC and MARS

	.EXAMPLE 
		PS C:\>.\Check-Proxy.ps1 -trace -test -all -List C:\temp\myurls.csv
        This will collect netsh trace, run test of the URI from the list provided and retrieve proxy info for all installed modules used on HCI
 
 	.EXAMPLE 
		PS C:\>.\Check-Proxy.ps1 -all
        This will retrieve proxy info for all installed modules used on HCI

	.NOTES 
		Author: Benjamin Bouckenooghe
        Creation date: 2022/05/20
        Last modification: 2022/05/30
        Disclaimer: This script is provided 'as-is' and Microsoft does not assume any liability. This script may be redistributed as long as the file contains these terms of use unmodified. 
		Caution: as this script not signed, think to run from elevated privileges the command "set-executionpolicy unrestricted"
        ChangeLog:
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
#>
 


param(
[switch]$trace,
[switch]$test,
[switch]$hci,
[switch]$aks,
[switch]$arc,
[switch]$mars,
[switch]$all,
[string]$List = ".\default-test-list.txt"
)

# Variable
$outPath = "C:\MS"
if(test-path $outPath){write-host "Files will be stored in $outPath"}
else{New-Item -Path "c:\" -Name "MS" -ItemType "directory" | Out-Null}
$AllUsersWinInetProxySet = $false

# Create folder using Date
$itemName = "$((Get-Date).Year)"+"-"+"$((Get-Date).Month)"+"-"+"$((Get-Date).Day)"+"_"+"$((Get-Date).Hour)"+"-"+"$((Get-Date).Minute)"
New-Item -Path "C:\MS" -Name $itemName -ItemType "directory" | Out-Null
$outPlace = "C:\MS\"+$itemName
$outLog = $outPlace+"\proxy.log"

# Functions

Function Write-Log(){

    Write-Host -ForegroundColor $thisColor $thisMsg
    Write-host ""
    Write-Output $thisMsg | Out-File -FilePath $outLog -Append
    Write-Output "" | Out-File -FilePath $outLog -Append

    }

Function CheckUrl() {

    write-host -ForegroundColor Cyan "`n--> Testing $target"
    write-output "" | Out-File -FilePath $outLog -Append
    write-output "--> Testing $target" | Out-File -FilePath $outLog -Append

    if($(Resolve-DnsName -Name $target -DnsOnly) -ne $null){

        $fullTarget = "https://"+$target

        try{$urlTest = Invoke-WebRequest -Uri $fullTarget -UseBasicParsing | % {$_.StatusCode}}
        catch{
            Write-Output "Fails to establish connection: $($_.ToString())"
            Write-Output "Fails to establish connection: $($_.ToString())" | Out-File -FilePath $outLog -Append}
        
        if($urlTest -ne 200){write-host -ForegroundColor Red "`tConnection failed for $fullTarget"}
        elseif($urlTest -eq 207){write-host -ForegroundColor Yellow "`tConnection need authentication for $fullTarget"}
        else{write-host -ForegroundColor Green "`tConnection succeed for $fullTarget with status $urlTest"}

        Write-output "Connection succeed with status $urlTest for $target" | Out-File -FilePath $outLog -Append
        
        }
    else{
        write-host -ForegroundColor Red "`tName resolution failure for $target"
        Write-output "" | Out-File -FilePath $outLog -Append
        Write-output  "Name resolution failure for $target" | Out-File -FilePath $outLog -Append
        }
}

#Retrieve the context
$Computer = $env:COMPUTERNAME
$User = "$env:USERDOMAIN\$env:USERNAME"
$thisColor = "White" ; $thisMsg =  "Scrip start $(Get-Date)`nOn computer:`t$Computer`nFor user:`t$User" ; Write-Log

#Dump the DNS and Net Route configuration
$thisColor = "White" ; $thisMsg = "`n----------- DNS configuration ------------" ; Write-Log
Get-DnsClientServerAddress
Get-DnsClientServerAddress | Out-File -FilePath $outLog -Append

$thisColor = "White" ; $thisMsg = "`n-----------Network Routing information ------------" ; Write-Log
Get-NetRoute | ft
Get-NetRoute | ft | Out-File -FilePath $outLog -Append

#Dump the proxy using netsh 
$thisColor = "White" ; $thisMsg = "`n----------- Checking NETSH settings ------------" ; Write-Log
$cde = "netsh winhttp show proxy"
$result = cmd /c $cde
if ($result -match "Direct access"){$thisColor = "Yellow" ; $thisMsg = "`nNo proxy configuration set with NETSH" ; Write-Log}
else{$thisColor = "Cyan" ; $thisMsg = "`nProxy configuration set with NETSH`n $result" ; Write-Log}

#Dump the environment variables
$thisColor = "White" ; $thisMsg = "`n----------- Checking Machine variable environment ------------" ; Write-Log
$machine_http_proxy = [System.Environment]::GetEnvironmentVariable("http_proxy","machine")
$machine_https_proxy = [System.Environment]::GetEnvironmentVariable("https_proxy","machine")
If(($machine_http_proxy -ne $null) -or ($machine_https_proxy -ne $null)){$thisColor = "Yellow" ; $thisMsg = "`nProxy configuration in environment variables for $computer`nHTTP`t$machine_http_proxy`nHHTPS`t$machine_https_proxy" ; Write-Log}
else{$thisColor = "Cyan" ; $thisMsg = "`nNo proxy configuration in environment variables for $computer" ; Write-Log}

#Check also in the registry
$thisColor = "White" ; $thisMsg = "`n----------- Checking Users variable environment ------------" ; Write-Log
$regUsers = Get-Childitem -path Registry::HKEY_USERS 
$regUsers | % {
        $tempName = $_.Name
        if($tempName -notmatch "classe"){
            $tempReg = "Registry::$tempName\Environment"
            try{
                Get-Item -Path $tempReg | Select-Object -ExpandProperty Property | % {
                    if($_ -match "proxy")
                        {
                            $SID = $tempName.Split("\")[1]
                            $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
                            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
                            $thisColor = "Yellow" ; $thisMsg = "`nFound $_ entry in $tempName\Environment hive of account $objUser" ; Write-Log
                        }
                    }
                }
            catch{
                    Write-Output "Exception when checking proxy settings: $($_.ToString())" | Out-File -FilePath $outLog -Append
                }
        }
    }

$thisColor = "White" ; $thisMsg = "`n----------- Checking WinInet in registry -----------" ; Write-Log

try{
    if($(Get-ItemPropertyValue -Path REGISTRY::"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable) -eq 1){
        $thisColor = "Yellow" ; $thisMsg = "`nWinInet Machine proxy is enable" ; Write-Log
        $thisColor = "Yellow" ; $thisMsg = "`tProxy server:`t$(Get-ItemPropertyValue -Path REGISTRY::"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer)" ; Write-Log
        $thisColor = "Yellow" ; $thisMsg = "`tProxy bypass:`t$(Get-ItemPropertyValue -Path REGISTRY::"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride)" ; Write-Log
        $AllUsersWinInetProxySet = $true
        }
    }
catch{
      Write-Output "Exception when checking proxy settings in HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings: $($_.ToString())" | Out-File -FilePath $outLog -Append
    }

$regUsers = Get-Childitem -path Registry::HKEY_USERS 
$regUsers | % {
        $tempName = $_.Name
        if($tempName -notmatch "classe"){
            $tempReg = "Registry::$tempName\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            try{if($(Get-ItemPropertyValue -Path $tempReg -Name ProxyEnable) -eq 1)
                    {
                        $SID = $tempName.Split("\")[1]
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
                        $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
                        $thisColor = "Yellow" ; $thisMsg = "`nWinInet proxy found in $tempName\Software\Microsoft\Windows\CurrentVersion\Internet Settings hive of account $objUser" ; Write-Log
                        $thisColor = "Yellow" ; $thisMsg = "`tProxy server:`t$(Get-ItemPropertyValue -Path $tempReg -Name ProxyServer)" ; Write-Log
                        $thisColor = "Yellow" ; $thisMsg = "`tProxy bypass:`t$(Get-ItemPropertyValue -Path $tempReg -Name ProxyOverride)" ; Write-Log
                    }
                }
            catch{
                    Write-Output "Fail to dump $tempReg $($_.ToString())" | Out-File -FilePath $outLog -Append
                }
            }
        }       

#Check also in group policy
$thisColor = "White" ; $thisMsg = "`n----------- Checking WinInet in Group Policies ------------" ; Write-Log

try{
    if($(Get-ItemPropertyValue -Path REGISTRY::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable) -eq 1){
        $thisColor = "Yellow" ; $thisMsg = "`nWinInet Machine proxy is enable by GPO" ; Write-Log
        $thisColor = "Yellow" ; $thisMsg = "`tProxy server:`t$(Get-ItemPropertyValue -Path REGISTRY::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer)" ; Write-Log
        $thisColor = "Yellow" ; $thisMsg = "`tProxy bypass:`t$(Get-ItemPropertyValue -Path REGISTRY::"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride)" ; Write-Log
        }
    }
catch{
       Write-Output "Exception when checking proxy in GPOs: $($_.ToString())" | Out-File -FilePath $outLog -Append
    }

#Check also using WPAD
    # Through DNS
    $thisColor = "White" ; $thisMsg = "`n----------- Checking if WPAD is accessible using either DHCP or DNS ------------" ; Write-Log
    $myDNSsuffixes = $(Get-DnsClientGlobalSetting).SuffixSearchList
    if($myDNSsuffixes.count -ge 1){
        $myDNSsuffixes | % {
                $myWPAD = "wpad."+$_
                if($(Resolve-DnsName -Name $myWPAD -DnsOnly)){$thisColor = "Yellow" ; $thisMsg = "`tWPAD entry found: $(Resolve-DnsName -Name $myWPAD -DnsOnly)" ; Write-Log}
                else{$thisColor = "Green" ; $thisMsg = "`tNo WPAD entry found" ; Write-Log}
            }
        }
    else{
            $myWPAD = "wpad."+$myDNSsuffixes
            if($(Resolve-DnsName -Name $myWPAD -DnsOnly)){$thisColor = "Yellow" ; $thisMsg = "`tWPAD entry found: $(Resolve-DnsName -Name $myWPAD -DnsOnly)" ; Write-Log}
            else{$thisColor = "Green" ; $thisMsg = "`tNo WPAD entry found" ; Write-Log}
        }
    
    <#
    # Trhough option 252 in DHCP leases
    Install-Module -Name DHCPClient -Force -Confirm:$false
    Import-Module -Name DHCPClient
    Get-DHCPOptionString -OptionID 252
    #>


#Check in AKS proxy configration
if(($aks) -or ($all)){
    $thisColor = "White" ; $thisMsg = "`n-----------Looking for AKS proxy configuration ------------" ; Write-Log
    Get-AksHciProxySetting
    Get-AksHciProxySetting | Out-File -FilePath $outLog -Append
}

#Check in ARC proxy configration
if(($arc) -or ($all)){
    $thisColor = "White" ; $thisMsg = "`n-----------Looking for ARC agent proxy configuration ------------" ; Write-Log
    
    $result = azcmagent config get proxy.url
    $result | Out-File -FilePath $outLog -Append
}

#Check in MARS proxy configuration
    #Currently not yet implemented because it fully use the user WinInet proxy information
if(($mars) -or ($all)){    }

if($trace){
    $thisColor = "White" ; $thisMsg = "`n-----------Start network trace with Winhttp tracing ------------" ; Write-Log
    
    #Select the NIC that have the DNS server configured for the trace to avoid collection storage or internal traffic not Internet related
        $theseNICs = Get-DnsClientServerAddress | ? ServerAddresses -notmatch "fec"
        if($theseNICs.count -le 1){$thisNIC = $theseNICs.InterfaceAlias ; $thisColor = "White" ; $thisMsg = "NIC name is $thisNIC" ; Write-Log}
        $thisNICguid = $(Get-NetAdapter -Name $thisNIC | select InterfaceGuid).InterfaceGuid
    
    $cde = "netsh trace start capture=yes CaptureInterface=$thisNICguid tracefile=$outPlace\proxy.etl scenario=NetConnection,InternetClient_dbg maxSize=2048 PacketTruncateBytes=200 overwrite=yes"
    $thisColor = "Gray" ; $thisMsg = "Running command: 'netsh trace start capture=yes CaptureInterface=$thisNICguid tracefile=$outPlace\proxy.etl scenario=NetConnection,InternetClient_dbg maxSize=2048 PacketTruncateBytes=200 overwrite=yes'" ; Write-Log
        
    cmd /c $cde
}

if($test){
    $thisColor = "White" ; $thisMsg = "`n-----------Testing connectivity ------------" ; Write-Log

    if($List -eq ".\default-test-list.txt"){
        $URLs = @("login.microsoftonline.com";"graph.windows.net";"management.azure.com";"azurestackhci.azurefd.net";"login.microsoftonline.com";"edgesupprdwestuufrontend.westus2.cloudapp.azure.com";"edgesupprdwesteufrontend.westeurope.cloudapp.azure.com";"edgesupprdeastusfrontend.eastus.cloudapp.azure.com";"edgesupprdwestcufrontend.westcentralus.cloudapp.azure.com";"edgesupprdasiasefrontend.southeastasia.cloudapp.azure.com";"edgesupprd.trafficmanager.net";"www.powershellgallery.com/packages/Az.StackHCI";"windowsupdate.microsoft.com";"update.microsoft.com";"windowsupdate.com";"download.windowsupdate.com";"download.microsoft.com";"wustat.windows.com";"ntservicepack.microsoft.com";"go.microsoft.com";"dl.delivery.mp.microsoft.com";"dl.delivery.mp.microsoft.com")
        }
    else{
        $URLs = Import-Csv -Path $List
    }

    $URLs | % {
        try{
            if($List -eq ".\default-test-list.txt"){$tempTarget = $_}else{$tempTarget = $_.URI}
            $target = $tempTarget.Split("/")[0]

            CheckUrl

            }
        catch{
            Write-Output "Exception trying to use URIs: $($_.ToString())"
            Write-Output "Exception trying to use URIs: $($_.ToString())" | Out-File -FilePath $outLog -Append
            }
        }
    #Dump the DNS cache before to exist the test loop
    $thisColor = "White" ; $thisMsg = "`n-----------DNS Client cache output ------------" ; Write-Log
    Get-DnsClientCache | Out-File -FilePath $outLog -Append
}

if(($hci) -or ($all)){
    $thisColor = "White" ; $thisMsg = "`n-----------Looking for HCI endpoint status ------------" ; Write-Log
    Test-AzStackHCIConnection
    Test-AzStackHCIConnection | Out-File -FilePath $outLog -Append
}

if($trace){
    $thisColor = "White" ; $thisMsg = "`n-----------Stop network trace with Winhttp tracing ------------" ; Write-Log
    $cde = "netsh trace stop"
    cmd /c $cde
}

#Compress logs

Get-ChildItem -Path . | ? Name -match AzStackHCIRemoteSupport_ | Move-Item -Destination $outPlace
$thisArchive = "C:\MS\"+$env:COMPUTERNAME+"_"+$itemName+".zip"
Compress-Archive -Path $outPlace -DestinationPath $thisArchive
Remove-Item $outPlace -Force  -Recurse -ErrorAction SilentlyContinue

Write-Host "Please retrive the archive C:\MS\$itemName.zip and upload on the secure file transfer"
Write-Host "`n-----------End of script ------------"
