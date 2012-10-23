#while ($true) {
    $RemoteMailboxes = Get-RemoteMailbox | Where-Object {$_.RemoteRoutingAddress -like '*@whatcomtrans.net'}
    $RemoteMailboxes | ForEach-Object {Set-RemoteMailbox -identity ($_.UserPrincipalName) -RemoteRoutingAddress ($_.SamAccountName + '@whatcomtrans.mail.onmicrosoft.com') -Verbose}
    . .\Office365\Run-DirSync.ps1
    Sleep 300
#}