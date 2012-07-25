#New-SharedMailbox

#Requires the Office365PowerShellUtils module, see https://github.com/whatcomtrans/Office365PowershellUtils

#See http://help.outlook.com/140/ee441202.aspx
param(
    [String] $alias,
    [String] $name
)

$_mailboxalias = $alias
$_mailboxname = $name
$_PermissionGroup = "SHMB-$_mailboxalias"
$_AutoMapping = $true

$DirSyncHost = "SRVMSOL1"
$PermissionsOU = "OU=PermissionGroups,DC=whatcomtrans,DC=net"

#Create security group
New-ADGroup -Path $PermissionsOU -Name $_PermissionGroup -SamAccountName $_PermissionGroup -Description "Users and groups have FullAccess and SendAs permissions to the shared mailbox: $_mailboxalais"

#TODO - Force directory sync
$scb = {
    #Force DirSync
    Add-PSSnapin Coexistence-Configuration
    Start-OnlineCoexistenceSync
    Sleep 30
}
Invoke-Command -ComputerName $DirSyncHost -ScriptBlock $scb

#Create a shared mailbox
New-Mailbox -Name $_mailboxname -Alias $_mailboxalias -Shared
Set-Mailbox $_mailboxalias -ProhibitSendReceiveQuota 5GB -ProhibitSendQuota 4.75GB -IssueWarningQuota 4.5GB

#Assign the security group the fullAccess permission to access the shared mailbox
Add-MailboxPermission -Identity $_mailboxalias -User $_PermissionGroup -AccessRights FullAccess -AutoMapping:$_AutoMapping

#Assign the security gorup the SendAs permission to the shared mailbox
Add-RecipientPermission -Identity $_mailboxalias -Trustee $_PermissionGroup -AccessRights SendAs

#Add ridewta.com as primary SMTP address
Change-ProxyAddress -Identity $_mailboxalias -ProxyAddress "$_mailboxalias@ridewta.com" -IsDefault -Add

#TODO - Force directory sync
Invoke-Command -ComputerName $DirSyncHost -ScriptBlock $scb
