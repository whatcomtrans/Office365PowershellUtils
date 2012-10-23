$mbs = Get-Mailbox
$mbs | Set-Mailbox -RetentionPolicy "WTA Primary"
$mbs | ForEach-Object {Start-ManagedFolderAssistant -Identity ($_.Alias)}