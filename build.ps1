Import-Module PowerShellGet

#Publish to PSGallery and install/import locally

Publish-Module -Path .\ -Repository PSGallery -Verbose
Install-Module -Name Office365PowershellUtils -Repository PSGallery -Force
Import-Module -Name Office365PowershellUtils -Force