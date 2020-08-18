# Contributing

This project has adopted the [Microsoft Open Source Code of
Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct
FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com)
with any additional questions or comments.

## Best practices

* Use Windows PowerShell or [PowerShell Core][pwsh] (including on Linux/OSX) to run .ps1 scripts.
  Some scripts set environment variables to help you, but they are only retained if you use PowerShell as your shell.

## Prerequisites

Building this repo is only supported on Windows (although the produced binaries will run on any OS).

Most dependencies can be installed by running the `init.ps1` script at the root of the repository
using Windows PowerShell or [PowerShell Core][pwsh].

Visual Studio 2019 is also required, with at least the components identified in the `tools\.vsconfig` file,
which you can import as a configuration into the VS installer to conveniently install everything you need.

## Package restore

The easiest way to restore packages may be to run `init.ps1` which automatically authenticates
to the feeds that packages for this repo come from, if any.
`dotnet restore` or `nuget restore` also work but may require extra steps to authenticate to any applicable feeds.

## Building

This repository can be built on Windows, Linux, and OSX.

Building, testing, and packing this repository must be done with Visual Studio 2019 or msbuild.exe.

## Testing

Testing can be done by:

1. Running all tests in the Visual Studio Test Explorer.
1. Setting the PCLCrypto.Tests.Android project as the startup project and executing that as a mobile application the Android emulator or a real Android phone.

The UWP and Android tests do *not* run in Azure Pipelines at present, so please make sure to run all tests and see that they pass before submitting pull requests.

[pwsh]: https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-6
