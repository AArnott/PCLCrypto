$AndroidToolPath = "${env:ProgramFiles(x86)}\Android\android-sdk\tools\android.bat"

if (!(Test-Path $AndroidToolPath)) {
    $AndroidToolPath = "$env:localappdata\Android\android-sdk\tools\android.bat"
}

Function Get-AndroidSDKs() {
    $output = & $AndroidToolPath list sdk --all
    $sdks = $output |% {
        if ($_ -match '(?<index>\d+)- (?<sdk>.+), revision (?<revision>[\d\.]+)') {
            $sdk = New-Object PSObject
            Add-Member -InputObject $sdk -MemberType NoteProperty -Name Index -Value $Matches.index
            Add-Member -InputObject $sdk -MemberType NoteProperty -Name Name -Value $Matches.sdk
            Add-Member -InputObject $sdk -MemberType NoteProperty -Name Revision -Value $Matches.revision
            $sdk
        }
    }
    $sdks
}

Function Install-AndroidSDK() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [PSObject[]]$sdks
    )

    $sdkIndexes = $sdks |% { $_.Index }
    $sdkIndexArgument = [string]::Join(',',  $sdkIndexes)
    Write-Output "Installing additional Android SDKs..."
    $sdks | Format-Table Name

    # Suppress the output to STDOUT
    $null = Echo 'y' | & $AndroidToolPath update sdk -u -a -t $sdkIndexArgument
}

Function Install-Win81SDK {
    if (!(Test-Path "$PSScriptRoot\obj")) { $null = mkdir "$PSScriptRoot\obj" }
    $sdkSetupPath = "$PSScriptRoot\obj\Win8SDKSetup.exe"
    $sdkLogFile = "$PSScriptRoot\obj\win81sdk.log"
    if (!(Test-Path $sdkSetupPath)) {
        Write-Output "Downloading the Windows 8.1 SDK..."
        Invoke-WebRequest -Uri "http://go.microsoft.com/fwlink/p/?LinkId=323507" -OutFile $sdkSetupPath
    }

    Write-Output "Installing the Windows 8.1 SDK..."
    Start-Process $sdkSetupPath @('/features','+','/q','/l',$sdkLogFile)  -Wait
}

$sdks = Get-AndroidSDKs |? { $_.name -like 'sdk platform*API 10*' -or $_.name -like 'google apis*api 10' }

Install-Win81SDK
Install-AndroidSDK -sdks $sdks
