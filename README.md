PCLCrypto
=========
This provides portable class library authors with a PCL-compatible crypto library that invokes platform-specific crypto automatically.

### Features

 * Cryptographically strong random number generator 
 * Symmetric and asymmetric encryption and signatures 
 * Key derivation 
 * Native crypto performance for each platform. This provides a 2-100X perf improvement for RSA on Android and iOS. 
 * Support for multiple key formats (PKCS#1, PKCS#8, CAPI) on all platforms. 

The API is designed to be similar to that found on WinRT or the .NET Framework. However some code changes may be required if migrating to this library from platform-specific crypto.

### Installation

Add a dependency to this library into your project via the pre-built NuGet package: [PCLCrypto][4].

    Install-Package PclCrypto

Be sure to install the NuGet package into your Portable library as well as each platform-specific app that uses your portable library. If you're shipping your portable library on NuGet, be sure to specify PclCrypto as a NuGet package dependency of your own NuGet package and you're set.

Installing via NuGet is important because we use facade assemblies and platform-specific assemblies to allow your PCLs to access crypto that is normally available only to platform-specific libraries using a technique Paul Betts calls [Bait and switch PCLs][5]. NuGet handles all the magic for you. 

### Documentation

Online documentation is available on our [project wiki site][6].

### FAQ

1. How does this differ from the cryptography offered to PCLs in the [PCLContrib][1] project?

 * PCLCrypto is focused on just delivering cryptography, with a good level of unit testing that runs on all supported platforms.
 * PCLCrypto follows the NuGet consumption patterns of [PCLStorage][3], which makes it very easy to consume from both PCLs and your platform-specific apps.
 * PCLCrypto is under active development. PCLContrib [hasn't been updated in a while][2].

 [1]: https://pclcontrib.codeplex.com/
 [2]: https://pclcontrib.codeplex.com/SourceControl/list/changesets
 [3]: https://pclstorage.codeplex.com/
 [4]: http://nuget.org/packages/pclcrypto
 [5]: http://log.paulbetts.org/the-bait-and-switch-pcl-trick/
 [6]: https://github.com/aarnott/pclcrypto/wiki
