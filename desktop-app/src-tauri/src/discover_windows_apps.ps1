
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$name = $env:WORKSPACE_DESKTOP_APP
$exe = "$name.exe"
$processes = @(Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq (Get-Process -Id $PID).SessionId })
$commands = @{}
Get-CimInstance Win32_Process -Filter "Name = '$exe'" -ErrorAction SilentlyContinue | ForEach-Object {
    $commands[[int]$_.ProcessId] = $_.CommandLine
}
$list = @($processes | ForEach-Object {
    $process = $_
    @{ id = $process.Id; path = $process.Path; command = $commands[$process.Id] }
})
$packagePattern = if ($name -eq 'Claude') { '(^|[.])Claude($|[._\-])' } else { '^OpenAI[.](ChatGPT($|[-._])|Codex($|_))' }
$packages = @(Get-AppxPackage -Name "*$name*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $packagePattern })
if ($name -eq 'ChatGPT') { $packages += @(Get-AppxPackage -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue) }
$start = @(Get-StartApps -ErrorAction SilentlyContinue | Where-Object {
    $_.AppID -match $packagePattern -and $_.AppID -like '*!*'
})
$application = $null
foreach ($package in $packages) {
    $match = $start | Where-Object { $_.AppID -like "$($package.PackageFamilyName)!*" } | Select-Object -First 1
    if ($match) { $application = $match.AppID; break }
    $manifest = Get-AppxPackageManifest -Package $package.PackageFullName -ErrorAction SilentlyContinue
    $entries = @($manifest.Package.Applications.Application | Where-Object { $_.Id })
    $entry = $entries | Where-Object { $_.Id -eq 'App' -or [IO.Path]::GetFileName($_.Executable) -eq $exe } | Select-Object -First 1
    if (!$entry) { $entry = $entries | Select-Object -First 1 }
    if ($entry) { $application = "$($package.PackageFamilyName)!$($entry.Id)"; break }
}
if (!$application -and $start.Count) { $application = $start[0].AppID }
if ($application) {
    $family = ($application -split '!', 2)[0]
    $selectedPackage = $packages | Where-Object { $_.PackageFamilyName -eq $family } | Select-Object -First 1
    if ($selectedPackage -and $selectedPackage.InstallLocation) {
        $prefix = $selectedPackage.InstallLocation.TrimEnd('\') + '\'
        $sessionId = (Get-Process -Id $PID).SessionId
        $seen = @($list | ForEach-Object { $_.id })
        $packageProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.SessionId -eq $sessionId -and $seen -notcontains $_.Id -and
            $_.Path -and $_.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and
            ($_.ProcessName -in @($name, 'Codex'))
        }
        $list += @($packageProcesses | ForEach-Object {
            $cmd = Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue
            @{ id = $_.Id; path = $_.Path; command = $cmd.CommandLine }
        })
    }
}
$packageExecutable = $null
if ($selectedPackage -and $selectedPackage.InstallLocation) {
    $manifest = Get-AppxPackageManifest -Package $selectedPackage.PackageFullName -ErrorAction SilentlyContinue
    $entryId = ($application -split "!", 2)[1]
    $entry = $manifest.Package.Applications.Application | Where-Object { $_.Id -eq $entryId } | Select-Object -First 1
    if ($entry -and $entry.Executable -and ($entry.EntryPoint -eq "Windows.FullTrustApplication" -or $entry.TrustLevel -eq "mediumIL")) {
        $root = [IO.Path]::GetFullPath($selectedPackage.InstallLocation).TrimEnd("\") + "\"
        $candidate = [IO.Path]::GetFullPath((Join-Path $root $entry.Executable))
        if ($candidate.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $candidate) "resources\app.asar") -PathType Leaf)) {
            $packageExecutable = $candidate
        }
    }
}
$paths = @()
foreach ($root in @($env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
    if ($root) { $paths += (Join-Path $root "$name\$exe"), (Join-Path $root "OpenAI\$name\$exe") }
}
if ($name -eq 'Claude') {
    $paths += "$env:LOCALAPPDATA\AnthropicClaude\claude.exe", "$env:LOCALAPPDATA\Programs\Claude\Claude.exe"
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($entry in (Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Claude' })) {
        if ($entry.DisplayIcon -match '^\s*"?(.+?\.exe)"?(?:,\s*-?\d+)?\s*$') {
            $paths += [Environment]::ExpandEnvironmentVariables($Matches[1])
        }
        $root = [Environment]::ExpandEnvironmentVariables([string]$entry.InstallLocation).Trim('"')
        if (!$root -and $entry.UninstallString -match '^\s*"?(.+?\.exe)"?(?:\s|$)') {
            $root = Split-Path -Parent ([Environment]::ExpandEnvironmentVariables($Matches[1]))
        }
        if ($root -and [IO.Path]::IsPathRooted($root)) {
            $paths += Join-Path $root $exe
            $paths += @(Get-ChildItem -LiteralPath $root -Directory -Filter 'app-*' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | ForEach-Object { Join-Path $_.FullName $exe })
        }
    }
    $paths += @(Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\AnthropicClaude" -Directory -Filter 'app-*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | ForEach-Object { Join-Path $_.FullName $exe })
} else {
    $paths += "$env:LOCALAPPDATA\Programs\ChatGPT\ChatGPT.exe", "$env:LOCALAPPDATA\Programs\OpenAI\ChatGPT\ChatGPT.exe"
}
$paths = @($paths + @($list | ForEach-Object { $_.path }) | Where-Object {
    $_ -and [IO.Path]::IsPathRooted($_) -and [IO.Path]::GetFileName($_) -eq $exe -and
        $_ -notmatch '\\WindowsApps\\' -and (Test-Path -LiteralPath $_ -PathType Leaf)
})
@{ package = $application; package_executable = $packageExecutable; registered = [bool]($application -or $packages.Count); paths = @($paths); processes = @($list) } | ConvertTo-Json -Depth 4 -Compress
