Import-Module PowerShellGet

#Publish to PSGallery and install/import locally

Publish-Module -Path .\ -Repository PSGallery -Verbose
