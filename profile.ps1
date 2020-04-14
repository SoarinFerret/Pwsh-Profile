<############################################################################################################
#                                                   My Profile
#
#
#    Changelog:
#        20/04/11 - Begin redesign 
#                    remove legacy items
#                    move some code into separate module
#                    update prompt
#                    remove persistent history
#        19/06/07 - Added Use-SelfSignedCerts function
#                   Get-Goat updates
#        19/05/26 - Added ability to use profile in remote sessions
#                   Change changelog date format from MM/DD/YY to YY/MM/DD
#                   Update prompt to reflect remoting protocols
#        18/11/04 - Added alias for Get-Command as gcmd
#                   Update References to ProfilePath
#        18/09/15 - Updated prompt support for PowerShell Core
#        18/03/23 - Added Prompt customizations
#                   Added Persistent history
#        18/03/17 - Added New-Key
#                   Moved Credential import to function instead of execution
#                   Added local option for Update-Profile
#                   Invoke-Bsod
#        18/02/26 - Added Enable-RDP. Changed 'where' to 'Where-Object' in some functions
#        18/02/09 - Fixed Connect-ExchangeOnline bug
#        18/01/24 - Fixed Version bug. Added a Set-Location at the end.
#        17/12/31 - Added Hosts File Section which includes:
#                   Search-HostsFile
#                   Add-HostsFile
#                   Open-HostsFile
#        17/12/28 - PowerShell Core support for Get-XKCDPassword
#                   Removed unnecessary Cim call in Get-ComputerUptime
#        17/12/11 - PowerShell Core Support for Get-Goat
#        17/12/09 - PowerShell Core Support for Initial Setup
#                   Automated third version number based changelog
#        17/12/07 - Speed Optimization. Centralized Aliases Section
#        17/12/06 - Permanently moved to GitHub
#                   Added alias for grep, moved content, removed PSCX
#        17/12/03 - Overhaul of Connect-ExchangeOnline. Now checks for Modern Authentication
#        17/12/02 - Added Connect-SecurityAndComplianceCenter
#        17/10/22 - Added Resources Section which includes:
#                    Get-ComputerUtilization
#                    Get-ComputerCpuUtilization
#                    Get-ComputerMemoryUtilization
#                    Get-ComputerUptime
#        17/09/15 - Added Add-CredentialToCsv & changed credential handling in functions
#        17/09/14 - Added credential import from CSV
#                   Changed default module location to $ProfilePath\CstmModules
#                   Added Invoke-TextToSpeech
#        17/09/04 - Added Send-WakeOnLan
#        17/08/28 - Added Get-WindowsInstaller
#        17/08/03 - Added Resources section
#        17/07/19 - Added Get-HyperVHost
#        17/07/14 - Added Get-ExternalIPAddress
#        17/06/28 - Added Update-Profile for easy profile management & added cleanup
#        17/06/26 - v1 overhaul:
#                    $secret now brought in as secure string
#                    checks for existing profileKey even if not in default path
#                    new module handling
#                    Added Update Switch to update script and modules
#        06/25/17 - Added new alias & created connect-exchangeonline
#        06/20/17 - Added Get-goat
#        05/15/17 - Removed aggressive/unnecessary importing
#
############################################################################################################>
[CmdletBinding()]
Param(
    [Parameter(Position=0)]
    [string]$ProfilePath = $(Split-Path -Path $profile.CurrentUserAllHosts),
    [Parameter(Position=1)]
    [bool]$Remote = $false,
    [switch]$Version,
    [switch]$Update
)
$ProgressPreference='SilentlyContinue'
$PSProfileVersion = "Remote"
if(!$Remote){
    $PSProfileVersion = "1.4." + ((Get-Content $script:MyInvocation.MyCommand.Path | Select-String "/")[0].ToString().Split('-')[0] -replace '\D+(\d+)','$1')
}

#Print Profile Version & Exit
if ($Version.IsPresent) {
  $PSProfileVersion
  exit 0
}


#############################################################################################################
#
#                                           Custom Settings
#
#############################################################################################################

# Disable annoying beep on backspace
if ((Get-Command Set-PSReadlineOption -ErrorAction SilentlyContinue)) {Set-PSReadlineOption -BellStyle None}

# Customize my prompt
function Prompt{
    # Cache value so we can set it back later
    $realLASTEXITCODE = $LASTEXITCODE

    # whoami
    Write-Host "`n[" -NoNewline
    # Print elevation/remote status
    if($PSSenderInfo.ConnectionString -like "*wsman*"){
        Write-Host "(Remote-WSMan) " -ForegroundColor Red -NoNewline
    }
    elseif($PSSenderInfo){
        Write-Host "(Remote-SSH) " -ForegroundColor Red -NoNewline
    }
    elseif( ( $PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*" ) -and ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        Write-Host "(Elevated) " -ForegroundColor Red -NoNewline
    }
    Write-Host "$(whoami)" -NoNewline -ForegroundColor Green
    Write-Host "]: " -NoNewline

    # Print current working directory
    if($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*"){
        Write-Host "$($(Get-Location).Path -replace ($home).Replace('\','\\'), "~")\".Replace('\\','\').Replace("Microsoft.PowerShell.Core\FileSystem::",'\') -ForegroundColor DarkGray
    }else{
        Write-Host "$($(Get-Location).Path -replace ($home).Replace('\','\\'), "~")/".Replace('//','/').Replace("Microsoft.PowerShell.Core\FileSystem::",'/') -ForegroundColor DarkGray
    }

    # if not remote session, print hostname
    if(!$PSSenderInfo){
        if($PSVersionTable.OS -like "Darwin*"){ Write-Host "[$(scutil --get LocalHostName)]: " -NoNewline }
        else { Write-Host "[$(hostname)]: " -NoNewline }
    }

    # Set exitcode to its former glory
    $global:LASTEXITCODE = $realLASTEXITCODE

    # Return nested prompt level
    return "PS$('>' * ($nestedPromptLevel + 1)) "
}

#############################################################################################################
#
#                                           Useful/fun Functions
#
#############################################################################################################

# Add Private Repo
function Add-PrivateRepo {
    Param(
        $Name = "KantoRepo",
        $SourceLocation = "https://packages.kanto.cloud/repository/PowerShell/",
        $PublishLocation = "https://packages.kanto.cloud/repository/PowerShell/"
    )

    Register-PSRepository -Name KantoRepo `
                          -SourceLocation https://packages.kanto.cloud/repository/PowerShell/ `
                          -PublishLocation https://packages.kanto.cloud/repository/PowerShell/ `
                          -PackageManagementProvider nuget `
                          -InstallationPolicy Trusted `
                          -Credential (Get-Credential)
}

# Get-Time
function Get-Time {  return $(Get-Date).ToLongTimeString() }

# Get-HyperVHost
Function Get-HyperVHost {
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    Invoke-command -ComputerName $ComputerName -ScriptBlock {
        return $(get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName") 
    }
}

# update profile & modules
function Update-Profile {
    [CmdletBinding(DefaultParameterSetName='Remote')]
    Param(
        [Parameter(ParameterSetName='Local')]
        [String]$Path,
        [Parameter(ParameterSetName='Remote')]
        [string]$URI = "https://raw.githubusercontent.com/SoarinFerret/Pwsh-Profile/master/profile.ps1",
        [switch]$IncludeModules
    )
    # Copy from local location
    if($Path){
        if(Test-Path $Path){
            $confirm = Read-Host "This will overwrite the existing profile. Are you sure you want to proceed? (y/n)"
            if ($confirm -like "y*") {
                Copy-Item $Path -Destination "$ProfilePath\profile.ps1" -Force
            }
        }
    }
    else {
        Invoke-WebRequest -Uri $URI -OutFile "$ProfilePath\profile.ps1"
        # Need to unblock file for Windows hosts
        if($PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*"){
            Unblock-File "$ProfilePath\profile.ps1"
        }
    }
    if($IncludeModules){
        $updateCommand = "$ProfilePath\profile.ps1 -Update"
        Invoke-Expression $updateCommand
    }
}

# get profile version
function Get-ProfileVersion { invoke-expression "$ProfilePath\profile.ps1 -Version" }

# why goat farming is better than IT
Function Get-Goat {
    $OriginalPref = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"
    try{
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $URI = "http://www.heldeus.nl/goat/GoatFarming.html"
        $HTML = Invoke-WebRequest -Uri $URI -UseBasicParsing
        $response = ($HTML.Content.Remove(0,67) -split('<p class="goat">') |  Get-Random).TrimStart()
        Write-Host "Why Goatfarming is better than IT: $($response.Substring(0,$response.indexof('</p>')))"
    }catch{
        Write-Host "Why Goatfarming is better than IT: Goat farming doesn't require an internet connection."
    }
    $ProgressPreference = $OriginalPref
}

# Create Bsod
function Invoke-Bsod{
    Param(
        [String]$Computername = $env:COMPUTERNAME,
        [Pscredential]$Credential
    )
    Write-Host "This will cause a Blue Screen of Death on $Computername.`nAre you sure absolutely sure you want to proceed? (y/n): " -ForegroundColor Red -NoNewline
    $confirm = Read-Host 
    if ($confirm -notlike "y*") {
        return 0;
    }

    # splat invoke-command
    $params = @{}
    if ($computername -notlike $env:COMPUTERNAME -and `
        $ComputerName -notlike "localhost"){
        $params['ComputerName'] = $ComputerName
    }
    if ($Credential){ $params['Credential'] = $Credential }

    Invoke-Command @params -ScriptBlock {
        wmic process where processid!=0 call terminate
    }

}

Function Get-ExternalIPAddress{
    #stolen from https://gallery.technet.microsoft.com/scriptcenter/Get-ExternalPublic-IP-c1b601bb
    Param(
        [switch]$Full
    )
    if($full) {return Invoke-RestMethod http://ipinfo.io/json}
    else{return (Invoke-RestMethod http://ipinfo.io/json | Select-object -exp ip)}
}

# Useful on older versions of powershell
function Test-Admin {
    $admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (!($admin)){
        throw "You are not running as an administrator"
    }
    else {
        Write-Verbose "Got admin"
        return $true
    }
}

# Checks windows installer for what version of windows it contains
function Get-WindowsInstaller {
    param (
        [Parameter(Position=0,Mandatory=$true)][String]$DriveLetter
    )
    Test-Admin
    if(!(Get-Volume $DriveLetter[0] -ErrorAction SilentlyContinue)){throw "Volume with the property 'DriveLetter' equal to '$($DriveLetter[0])' cannot be found"}
    $file = "install.wim"
    if(Test-Path "$($DriveLetter[0]):\sources\install.esd"){ $file = "install.esd"}
    for($index = 1; $index -ne 0; $index++){
        $a = dism /Get-WimInfo /WimFile:$($DriveLetter[0])`:\sources\$file /index:$index | Select-String -Pattern "Name" -SimpleMatch
        
        if($a -ne $null){ write-host $a.ToString().SubString(7) }
        else { $index = -1 }
    }
}

# stolen from https://gallery.technet.microsoft.com/scriptcenter/Send-WOL-packet-using-0638be7b
function Send-WakeOnLan {
<# 
  .SYNOPSIS  
    Send a WOL packet to a broadcast address
  .PARAMETER mac
   The MAC address of the device that need to wake up
  .PARAMETER ip
   The IP address where the WOL packet will be sent to
  .EXAMPLE 
   Send-WOL -mac 00:11:32:21:2D:11 -ip 192.168.8.255 
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$MAC,
        [string]$IP="255.255.255.255", 
        [int]$Port=9
    )   
    $broadcast = [Net.IPAddress]::Parse($ip)
    $mac=(($mac.replace(":","")).replace("-","")).replace(".","")
    $target=0,2,4,6,8,10 | ForEach-Object {[convert]::ToByte($mac.substring($_,2),16)}
    $packet = (,[byte]255 * 6) + ($target * 16)
    $UDPclient = new-Object System.Net.Sockets.UdpClient
    $UDPclient.Connect($broadcast,$port)
    [void]$UDPclient.Send($packet, 102) 
}

# TODO: add option to send to different computer
function Invoke-TextToSpeech {
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)] [string] $Text)
    [Reflection.Assembly]::LoadWithPartialName('System.Speech') | Out-Null   
    $object = New-Object System.Speech.Synthesis.SpeechSynthesizer 
    $object.Speak($Text) 
}

# Get-XKCDPassword 2.0
# TODO: add more options
function Get-XKCDPassword {
    Param(
        [String]$Path = "$ProfilePath\dictionary.txt",
        [String]$Uri = "https://raw.githubusercontent.com/SoarinFerret/Pwsh-Profile/master/dictionary.txt",
        [Int32]$Count = 3,
        [switch]$UpdateDictionary
    )

    if($UpdateDictionary -or !(Test-Path $Path)){
        Write-Host "Updating Dictionary..." -ForegroundColor Green
        Remove-Item -Path $Path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Force
        Invoke-WebRequest -Uri $Uri -OutFile $Path
    }

    # Get words
    $words = Get-Content $Path | Get-Random -Count $($Count*3)

    # Generate Phrases
    $out = @(); for($x = 0; $x -lt $count; $x++){
        $pwd = $("{0:D2}" -f (Get-Random -Maximum 99))+`
               $words[$x*$count]+`
               $words[$x*$count+1].toUpper()+`
               $words[$x*$count+2]+`
               $("{0:D2}" -f (Get-Random -Maximum 99))
        $out += $pwd
    }
    return $out
}

function Enable-RemoteDesktop {
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential
    )
    # splat the computername and credential. 'Invoke-Command' is
    # much quicker if computername is not specified on localhost

    $credHash = @{}
    if ($computername -notlike $env:COMPUTERNAME -and `
        $ComputerName -notlike "localhost"){
        $credHash['ComputerName'] = $ComputerName
    }
    if ($Credential){ $credHash['Credential'] = $Credential }

    Invoke-Command @credhash -ScriptBlock{
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0;
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    }
}

# credit where credit is due: https://raw.githubusercontent.com/wazuh/wazuh-api/3.9/examples/api-register-agent.ps1
function Use-SelfSignedCerts {
    if($PSEdition -ne "Core"){
        add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class PolicyCert : ICertificatePolicy {
                public PolicyCert() {}
                public bool CheckValidationResult(
                    ServicePoint sPoint, X509Certificate cert,
                    WebRequest wRequest, int certProb) {
                    return true;
                }
            }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object PolicyCert
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    }else{
        Write-Warning -Message "Function not supported in PSCore. Just use the '-SkipCertificateCheck' flag"
    }
}

function Enter-EnhancedPSSession{
    Param(
        [Parameter(Position=0,Mandatory=$true,ParameterSetName="WSMAN")]
        [String]$ComputerName,
        [Parameter(Mandatory=$true,ParameterSetName="SSH")]
        [String]$Hostname,
        [Parameter(Position=1,ParameterSetName="WSMAN")]
        [pscredential]$Credential,
        [Parameter(Position=1,ParameterSetName="SSH")]
        [String]$username,
        [Parameter(Position=3)]
        [String]$ProfilePath = $profile.CurrentUserAllHosts
    )
    if($PSCmdlet.ParameterSetName -eq "WSMAN"){
        if ($Credential){
            $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
            $PSDefaultParameterValues['*:Credential'] = $Credential
        }
        $session = New-PSSession $ComputerName
    }else{
        if($username){
            $session = New-PSSession -Hostname $Hostname -Username $username
        }else{
            $session = New-PSSession -Hostname $Hostname
        }
    }
    if($session){
        Invoke-Command -Session $session -FilePath $ProfilePath -ArgumentList "",$true
        Enter-PSSession $session
    }
}

#############################################################################################################
#
#                                        Modern Authentication O365
#
#############################################################################################################

# connect to exchangeonline using modern authentication or basic
function Connect-ExchangeOnline {
    Param(
        [String]$UserPrincipalName = "",
        [PSCredential]$Credential = $null,
        [String]$ConnectionURI = 'https://outlook.office365.com/PowerShell-LiveId',
        [switch]$UseBasic
    )
    $PSSession = $null

    # Check if Exchange Online PowerShell module is installed, otherwise revert to old way
    $Module = "Microsoft.Exchange.Management.ExoPowershellModule.dll"
    if(!$UseBasic -and ($ModulePath = (Get-ChildItem $env:LOCALAPPDATA\Apps -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -like $Module -and $_.DirectoryName -like "*tion*"}))){
        $ModulePath= $ModulePath[0].FullName
        $global:ConnectionUri = $ConnectionUri
        $global:AzureADAuthorizationEndpointUri = 'https://login.windows.net/common'
        $global:UserPrincipalName = $UserPrincipalName
        Import-Module $ModulePath
        $PSSession = New-ExoPSSession -UserPrincipalName $UserPrincipalName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri
    }
    else{
        $PSSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionURI -AllowRedirection -Credential $Credential -Authentication Basic
    }
    if ($PSSession -ne $null) { Import-PSSession $PSSession -AllowClobber }
}

# connect to the security and compliance center using modern or basic authentication
function Connect-SecurityAndComplianceCenter {
    Param(
        $UserPrincipalName = "",
        [PSCredential]$Credential = $null,
        $ConnectionURI = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId',
        [switch]$UseBasic
    )
    $param = @{UserPrincipalName=$UserPrincipalName;Credential=$Credential;ConnectionURI=$ConnectionURI;UseBasic=$UseBasic}
    Connect-ExchangeOnline @param
}

#############################################################################################################
#
#                                             Hosts File
#
#############################################################################################################

# TODO: Remove-HostsFile

function Search-HostsFile {
    Param(
        [String]$Hostname = "*",
        [ipaddress]$IP = $null
    )
    $file = ""
    if($PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*"){
        $file = "$env:windir\System32\drivers\etc\hosts"
    } else { $file = "/etc/hosts" }
    $lines = Get-Content $file | Where-Object {$_[0] -ne '#' -and $_.trim() -ne "" -and $_ -like $Hostname}
    if($ipaddress -ne $null){
        $lines = $lines | Where-Object {$_ -like $ipaddress}
    }
    $hosts = @()
    forEach ($line in $lines){
        $parts = $line -replace "#.*" -split '\s+' # doesnt include EOL comments like this
        $ip = $parts[0]
        $names = $parts[1..($parts.Length-1)] | Where-Object {$_ -ne ""}
        $hosts += New-Object -TypeName psobject -Property @{IPAddress=$ip;Hostname=$names}
    }
    return $hosts
}

function Add-HostsFile {
    Param(
        [Parameter(Mandatory=$true)]
        [String[]]$Hostname,
        [Parameter(Mandatory=$true)]
        [ipaddress]$IP
    )
    Test-Admin
    $file = ""
    if($PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*"){
        $file = "$env:windir\System32\drivers\etc\hosts"
    } else { $file = "/etc/hosts" }
    "$($ip.IPAddressToString)`t$hostname" | Out-File $file -Append -Encoding ascii
}

function Open-HostsFile {
    Start-Process notepad "$env:windir\System32\drivers\etc\hosts"
}

#############################################################################################################
#
#                                   Get Cool Modules from Me/PSGallery
#
#############################################################################################################

function profileGetModules{ 
    #install NuGet
    if(!(Get-Module -ListAvailable -Name PackageManagement)){
        Get-PackageProvider -Name NuGet -Force | Out-Null
    }

    $modules = "NTFSSecurity","Posh-SSH","AzureAD"

    ForEach($module in $modules){
        if(!(Get-Module -ListAvailable -Name $module)){
            Find-Module $module
            Install-Module $module -Force -AllowClobber
        }else {Update-Module $module}
    }
}

#############################################################################################################
#
#                                              Aliases
#
#############################################################################################################

function profileSetAlias{
    Param(
        [parameter(Position=0)][String]$Alias,
        [parameter(Position=1)][String]$Command
    )
    if (!(Get-alias $Alias -ErrorAction SilentlyContinue) -and (Get-Command $Command -ErrorAction SilentlyContinue)){
        new-Alias $Alias $Command -Scope 1
    }
}

# Standard Cmdlets
profileSetAlias touch New-Item
profileSetAlias grep Select-String
profileSetAlias get-commands get-command #bc I always accidently type this instead
profileSetAlias gcmd get-command
profileSetAlias Shutdown-Computer Stop-Computer #because it makes more sense

# PS Core Aliases
profileSetAlias wget Invoke-WebRequest
profileSetAlias ls Get-ChildItem

# Hyper-V specific
profileSetAlias Shutdown-VM Stop-VM

# Active Directory specific
profileSetAlias Reset-ADAccountPassword Set-ADAccountPassword #because I cant remember this for some reason

# Useful / Fun Cstm Functions
profileSetAlias gt Get-Time
profileSetAlias gg Get-Goat
profileSetAlias geip Get-ExternalIPAddress
profileSetAlias Test-isAdmin Test-Admin
profileSetAlias Check-WindowsInstaller Get-WindowsInstaller
profileSetAlias Send-WOL Send-WakeOnLan
profileSetAlias gxp Get-XKCDPassword
profileSetAlias Enable-RDP Enable-RemoteDesktop
profileSetAlias eps Enter-EnhancedPSSession
profileSetAlias Ignore-SelfSignedCerts Use-SelfSignedCerts

# O365 Modern Auth
profileSetAlias Connect-Exo Connect-ExchangeOnline
profileSetAlias Connect-SaCC Connect-SecurityAndComplianceCenter

#############################################################################################################
#
#                                           Execution
#
#############################################################################################################

#if not ran in correct directory, get user input about stuff
if(!$Remote -and $(Split-Path $script:MyInvocation.MyCommand.Path) -ne $ProfilePath){
    $response = Read-Host "'$($MyInvocation.MyCommand)' was not run from its default location.`nWould you like to copy it there? This action will overwrite any previously created profile. (Y/N) "
    if($response -like "y*"){
        #create path if non-existent, otherwise copy item
        if(!(test-path $ProfilePath)){New-Item -Path $ProfilePath -ItemType Directory -Force}
        Copy-Item ".\$($MyInvocation.MyCommand)" -Destination "$ProfilePath\profile.ps1" -Force
    }
    else { $ProfilePath = (Get-Location).Path }
}

# Import custom modules
if(!$Remote -and (test-path $ProfilePath\CstmModules)){
    Get-ChildItem "$ProfilePath\CstmModules" | ForEach-Object{ Import-Module $_.FullName -Force -WarningAction SilentlyContinue }
}

$ProgressPreference='Continue'

# Clean up items
Remove-Item -Path Function:\profile*
Remove-Variable Update,Version

# Change Directory to $home
Set-Location $home
