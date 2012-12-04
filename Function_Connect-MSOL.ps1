function Connect-Office365 {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$false,ParameterSetName="",HelpMessage="Credentials")]
		[System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$false,ParameterSetName="",HelpMessage="Path to credentials")]
		[String]$CredentialPath
	)
    
    #Prompt for credential if not provided
    if (!$Credential -and !$CredentialPath) {
	    $Credential = Get-Credential #$env:username
    }
    if ($CredentialPath) {
        $Credential = Import-PSCredential -Path $CredentialPath
    }

    #Connect to MSOLService with credential
    Connect-MsolService -Credential $Credential

    #Connect to Exchange Online session and import
    New-Variable -Scope "Global" -Name ExchangeOnlineSession -Value(New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/PowerShell/ -Credential $Credential -Authentication Basic -AllowRedirection)
    #$ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/PowerShell/ -Credential $msolcred -Authentication Basic -AllowRedirection
    Import-PSSession $ExchangeOnlineSession -AllowClobber
    #$_mod = Get-Module -Name "tmp_*"
    #$_mod.AsCustomObject()
}