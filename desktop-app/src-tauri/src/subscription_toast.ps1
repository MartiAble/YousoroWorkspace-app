$ErrorActionPreference = 'Stop'
$startApp = Get-StartApps | Where-Object { $_.Name -eq 'Yousoro Workspace' } | Select-Object -First 1
if (-not $startApp.AppID) { throw 'Workspace Start menu shortcut is required' }
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
[void][Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType=WindowsRuntime]
$xml = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime]::new()
$text = [Security.SecurityElement]::Escape($env:WORKSPACE_NOTICE_TEXT)
$url = [Security.SecurityElement]::Escape($env:WORKSPACE_NOTICE_URL)
$action = [Security.SecurityElement]::Escape($env:WORKSPACE_NOTICE_ACTION)
$xml.LoadXml(@"
<toast activationType="protocol" launch="$url">
  <visual><binding template="ToastGeneric">
    <text>Yousoro Workspace</text><text>$text</text>
  </binding></visual>
  <actions><action content="$action" activationType="protocol" arguments="$url" /></actions>
</toast>
"@)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($startApp.AppID).Show($toast)
