function Connect-Office365 {
	[CmdletBinding(SupportsShouldProcess=$false, DefaultParameterSetName="Username")]
	Param(
		[Parameter(Mandatory=$false,ParameterSetName="Username",HelpMessage="Credentials")]
		    [String]$Username,
		[Parameter(Mandatory=$false,ParameterSetName="Credentials",HelpMessage="Credentials")]
		    [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory=$false,ParameterSetName="CredentialsFile", HelpMessage="Path to credentials")]
		    [String]$CredentialPath,
        [Parameter(Mandatory=$false,HelpMessage="Forces re-connection when already connected.")]
		    [Switch]$Force
	)
    #First, test if already connected
    $existingConnection = $false
    $existingSession = Get-PSSession -Verbose:$false | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange"} 
    if ($existingSession -ne $null) {
        $existingConnection = $true
    }

    if (!($existingConnection) -or ($Force)) {

        #Prompt for credential if not provided
        if (!$Credential -and !$CredentialPath -and !$Username) {
	        $Credential = Get-Credential
        }
        if ($CredentialPath) {
            $Credential = Import-PSCredential -Path $CredentialPath
        }
        if ($Username) {
            $Credential = Get-Credential -UserName $Username -Message "Office 365 Credentials"
        }

        #Connect to MSOLService with credential
        Connect-MsolService -Credential $Credential

        #Connect to Exchange Online session and import
        New-Variable -Scope "Global" -Name ExchangeOnlineSession -Value(New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/PowerShell/ -Credential $Credential -Authentication Basic -AllowRedirection)
        #$ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/PowerShell/ -Credential $msolcred -Authentication Basic -AllowRedirection
        Import-PSSession $ExchangeOnlineSession -AllowClobber
        #$_mod = Get-Module -Name "tmp_*"
        #$_mod.AsCustomObject()

        if (Get-Module Microsoft.Online.SharePoint.PowerShell) {
            Connect-SPOService -Credential $Credential
        }
    }
}