[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='high')]
Param(
)

if (-not "$env:JAVA_HOME") {
    if ($PSCmdlet.ShouldProcess("Install JRE")) {
        Write-Host "Downloading Java Runtime Environment" -ForegroundColor Yellow
        Invoke-WebRequest -OutFile "$env:TEMP\jre.exe" http://download.oracle.com/otn-pub/java/jdk/10.0.1+10/fb4372174a714e6b8c52526dc134031e/jre-10.0.1_windows-x64_bin.exe
        Write-Host "Installing Java Runtime Environment" -ForegroundColor Yellow
        Start-Process "$env:TEMP\jre.exe" @('INSTALL_SILENT=Enable', 'INSTALL_DIR=C:\Program Files (x86)\Java') -Wait
        $env:JAVA_HOME = "C:\Program Files (x86)\Java"
    }
}

$AndroidToolPath = "${env:ProgramFiles(x86)}\Android\android-sdk\tools\bin\sdkmanager.bat"

if (!(Test-Path $AndroidToolPath)) {
    $AndroidToolPath = "$env:localappdata\Android\android-sdk\tools\bin\sdkmanager.bat"
}

Function Install-Win81SDK {
    if (!(Test-Path "$PSScriptRoot\obj")) { $null = mkdir "$PSScriptRoot\obj" }
    $sdkSetupPath = "$PSScriptRoot\obj\Win8SDKSetup.exe"
    $sdkLogFile = "$PSScriptRoot\obj\win81sdk.log"
    if (!(Test-Path $sdkSetupPath)) {
        Write-Host "Downloading the Windows 8.1 SDK..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri "http://go.microsoft.com/fwlink/p/?LinkId=323507" -OutFile $sdkSetupPath
    }

    Write-Host "Installing the Windows 8.1 SDK..." -ForegroundColor Yellow
    Start-Process $sdkSetupPath @('/features','+','/q','/l',$sdkLogFile)  -Wait
}

if ($PSCmdlet.ShouldProcess("Install Windows 8.1 SDK")) {
    Install-Win81SDK
}

if ($PSCmdlet.ShouldProcess("Install Android SDK 10")) {
    Write-Host "Installing Android SDK" -ForegroundColor Yellow
    Write-Output "y" | & $AndroidToolPath "platforms;android-10"
}
