$mbs = Get-Mailbox
$mbs | Set-Mailbox -RoleAssignmentPolicy "WTA Users"
