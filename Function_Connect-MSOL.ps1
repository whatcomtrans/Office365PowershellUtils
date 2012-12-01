function Connect-Office365 {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$false,HelpMessage="Credentials")]
		[System.Management.Automation.PSCredential]$msolcred
	)
	
    #Prompt for credential if not provided
    if (!$msolcred) {
	    $msolcred=Get-Credential #$env:username
    }

    #Connect to MSOLService with credential
    Connect-MsolService -Credential $msolcred

    #Connect to Exchange Online session and import
    New-Variable -Scope "Global" -Name ExchangeOnlineSession -Value(New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/PowerShell/ -Credential $msolcred -Authentication Basic -AllowRedirection)
    #$ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/PowerShell/ -Credential $msolcred -Authentication Basic -AllowRedirection
    Import-PSSession $ExchangeOnlineSession -AllowClobber
    #$_mod = Get-Module -Name "tmp_*"
    #$_mod.AsCustomObject()
}