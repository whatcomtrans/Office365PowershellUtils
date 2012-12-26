function Connect-Office365 {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$false,Position=1,HelpMessage="Credentials")]
		    [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory=$false,HelpMessage="Path to credentials")]
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
}