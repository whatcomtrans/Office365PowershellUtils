# Author: 	Hal Rottenberg <hal@halr9000.com>
# Url:		http://halr9000.com/article/tag/lib-authentication.ps1
# Purpose:	These functions allow one to easily save network credentials to disk in a relatively
#			secure manner.  The resulting on-disk credential file can only [1] be decrypted
#			by the same user account which performed the encryption.  For more details, see
#			the help files for ConvertFrom-SecureString and ConvertTo-SecureString as well as
#			MSDN pages about Windows Data Protection API.
#			[1]: So far as I know today.  Next week I'm sure a script kiddie will break it.
#
# Usage:	Export-PSCredential [-Credential <PSCredential object>] [-Path <file to export>]
#			Export-PSCredential [-Credential <username>] [-Path <file to export>]
#			If Credential is not specififed, user is prompted by Get-Credential cmdlet.
#			If a username is specified, then Get-Credential will prompt for password.
#			If the Path is not specififed, it will default to "./credentials.enc.xml".
#			Output: FileInfo object referring to saved credentials
#
#			Import-PSCredential [-Path <file to import>]
#
#			If not specififed, Path is "./credentials.enc.xml".
#			Output: PSCredential object

function Export-PSCredential {
	param ( $Credential = (Get-Credential), $Path = "credentials.enc.xml" )

	# Look at the object type of the $Credential parameter to determine how to handle it
	switch ( $Credential.GetType().Name ) {
		# It is a credential, so continue
		PSCredential		{ continue }
		# It is a string, so use that as the username and prompt for the password
		String				{ $Credential = Get-Credential -credential $Credential }
		# In all other caess, throw an error and exit
		default				{ Throw "You must specify a credential object to export to disk." }
	}
	
	# Create temporary object to be serialized to disk
	$export = "" | Select-Object Username, EncryptedPassword
	
	# Give object a type name which can be identified later
	$export.PSObject.TypeNames.Insert(0,’ExportedPSCredential’)
	
	$export.Username = $Credential.Username

	# Encrypt SecureString password using Data Protection API
	# Only the current user account can decrypt this cipher
	$export.EncryptedPassword = $Credential.Password | ConvertFrom-SecureString

	# Export using the Export-Clixml cmdlet
	$export | Export-Clixml $Path
	Write-Host -foregroundcolor Green "Credentials saved to: " -noNewLine

	# Return FileInfo object referring to saved credentials
	Get-Item $Path
}

function Import-PSCredential {
	param ( $Path = "credentials.enc.xml" )

	# Import credential file
	$import = Import-Clixml $Path 
	
	# Test for valid import
	if ( !$import.UserName -or !$import.EncryptedPassword ) {
		Throw "Input is not a valid ExportedPSCredential object, exiting."
	}
	$Username = $import.Username
	
	# Decrypt the password and store as a SecureString object for safekeeping
	$SecurePass = $import.EncryptedPassword | ConvertTo-SecureString
	
	# Build the new credential object
	$Credential = New-Object System.Management.Automation.PSCredential $Username, $SecurePass
	Write-Output $Credential
}

Export-ModuleMember -Function "Export-PSCredential", "Import-PSCredential"
