param([System.Management.Automation.PSCredential]$msolcred)

#Prompt for credential if not provided
if (!$msolcred) {
	$msolcred=Get-Credential
}

#Import MSOnline module
Import-Module MSOnline

#Connect to MSOLService with credential
Connect-MsolService -Credential $msolcred

#Connect to Exchange Online session and import
$EOSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/PowerShell/ -Credential $msolcred -Authentication Basic -AllowRedirection
Import-PSSession $EOSession -AllowClobber
