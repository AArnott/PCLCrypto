if (-not "$env:JAVA_HOME") {
    Invoke-WebRequest -OutFile "$env:TEMP\jre.exe" http://download.oracle.com/otn-pub/java/jdk/10.0.1+10/fb4372174a714e6b8c52526dc134031e/jre-10.0.1_windows-x64_bin.exe
    Start-Process "$env:TEMP\jre.exe" @('INSTALL_SILENT=Enable', 'INSTALL_DIR=C:\Program Files (x86)\Java') -Wait
    $env:JAVA_HOME = "C:\Program Files (x86)\Java"
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
        Write-Output "Downloading the Windows 8.1 SDK..."
        Invoke-WebRequest -Uri "http://go.microsoft.com/fwlink/p/?LinkId=323507" -OutFile $sdkSetupPath
    }

    Write-Output "Installing the Windows 8.1 SDK..."
    Start-Process $sdkSetupPath @('/features','+','/q','/l',$sdkLogFile)  -Wait
}

Install-Win81SDK
& $AndroidToolPath "platforms;android-10"
