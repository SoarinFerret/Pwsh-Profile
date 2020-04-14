<############################################################################################################
#                                                   My Profile
#
#
#    Changelog:
#        20/04/13 - v2 - Begin redesign 
#                    remove legacy items
#                    move some code into separate modules
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
    [string]$ProfilePath = $profile.CurrentUserAllHosts,
    [Parameter(Position=1)]
    [bool]$Remote = $false,
    [switch]$Version,
    [switch]$Update
)
$ProgressPreference='SilentlyContinue'
$PSProfileVersion = "Remote"
if(!$Remote){
    $PSProfileVersion = "2.0." + ((Get-Content $script:MyInvocation.MyCommand.Path | Select-String "/")[0].ToString().Split('-')[0] -replace '\D+(\d+)','$1')
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

    Register-PSRepository -Name $Name `
                          -SourceLocation $SourceLocation `
                          -PublishLocation $PublishLocation `
                          -PackageManagementProvider nuget `
                          -InstallationPolicy Trusted `
                          -Credential (Get-Credential)
}

# Get-Time
function Get-Time {  return $(Get-Date).ToLongTimeString() }

# update profile & modules
function Update-Profile {
    [CmdletBinding(DefaultParameterSetName='Remote')]
    Param(
        [Parameter(ParameterSetName='Local')]
        [String]$Path,
        [Parameter(ParameterSetName='Remote')]
        [string]$URI = "https://raw.githubusercontent.com/SoarinFerret/Pwsh-Profile/master/profile.ps1",
        [String]$ProfilePath = $profile.CurrentUserAllHosts
    )
    # Copy from local location
    if($Path){
        if(Test-Path $Path){
            $confirm = Read-Host "This will overwrite the existing profile. Are you sure you want to proceed? (y/n)"
            if ($confirm -like "y*") {
                Copy-Item $Path -Destination $ProfilePath -Force
            }
        }
    }
    else {
        Invoke-WebRequest -Uri $URI -OutFile $ProfilePath
        # Need to unblock file for Windows hosts
        if($PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*"){
            Unblock-File "$ProfilePath"
        }
    }
}

# get profile version
function Get-ProfileVersion {
    Param(
        [String]$ProfilePath = $profile.CurrentUserAllHosts
    ) 
    invoke-expression "$ProfilePath -Version" 
}

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

Function Get-ExternalIPAddress{
    #stolen from https://gallery.technet.microsoft.com/scriptcenter/Get-ExternalPublic-IP-c1b601bb
    Param(
        [switch]$Full
    )
    if($full) {return Invoke-RestMethod http://ipinfo.io/json}
    else{return (Invoke-RestMethod http://ipinfo.io/json | Select-object -exp ip)}
}

# Get-XKCDPassword 2.0
# TODO: add more options
function Get-XKCDPassword {
    Param(
        [String]$Path = "$(split-path $profile.CurrentUserAllHosts)\dictionary.txt",
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

function Set-LocationToHome{
    Set-Location ~/
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
    if( !(Get-Command $alias -ErrorAction SilentlyContinue) -and `  # check alias isn't already a command
        !(Get-alias $Alias -ErrorAction SilentlyContinue) -and `    # check alias doesn't exist
         (Get-Command $Command -ErrorAction SilentlyContinue)       # check command exists
      ){ 
        new-Alias $Alias $Command -Scope 1
    }
}

# Standard Cmdlets
profileSetAlias touch New-Item
profileSetAlias grep Select-String

# PS Core Aliases
profileSetAlias wget Invoke-WebRequest
profileSetAlias ls Get-ChildItem

# Active Directory specific
profileSetAlias Reset-ADAccountPassword Set-ADAccountPassword #because I cant remember this for some reason

# Useful / Fun Cstm Functions
profileSetAlias gg Get-Goat
profileSetAlias geip Get-ExternalIPAddress
profileSetAlias eps Enter-PSSession
profileSetAlias eeps Enter-EnhancedPSSession
profileSetAlias Ignore-SelfSignedCerts Use-SelfSignedCerts
profileSetAlias gh Set-LocationToHome

#############################################################################################################
#
#                                           Execution
#
#############################################################################################################

#if not ran in correct directory, get user input about stuff
if(!$Remote -and $script:MyInvocation.MyCommand.Path -ne $ProfilePath){
    $response = Read-Host "'$($MyInvocation.MyCommand)' was not run from its default location.`nWould you like to copy it there? This action will overwrite any previously created profile. (y/N) "
    if($response -like "y*"){
        #create path if non-existent, otherwise copy item
        if(!(test-path $(Split-Path $ProfilePath))){New-Item -Path $(Split-Path $ProfilePath) -ItemType Directory -Force}
        Copy-Item ".\$($MyInvocation.MyCommand)" -Destination $ProfilePath -Force
    }
    else { $ProfilePath = (Get-Location).Path }
}

$ProgressPreference='Continue'

# Clean up items
Remove-Item -Path Function:\profile*
Remove-Variable Update,Version,ProfilePath