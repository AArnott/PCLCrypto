PCLCrypto
=========

PCLCrypto provides cryptographic APIs over algorithms implemented by the platform, including exposing them to portable libraries.
PCLCrypto does not implement any crypto directly, thus making this library a good choice for applications that require the assurance of high quality crypto implementations that can most reliably be found within the operating system itself or hardware.

[![Build status](https://ci.appveyor.com/api/projects/status/0xtawuc0qg50vf2p/branch/master?svg=true)](https://ci.appveyor.com/project/AArnott/pclcrypto/branch/master)
[![NuGet package](https://buildstats.info/nuget/PCLCrypto?includePreReleases=true)](https://nuget.org/packages/PCLCrypto)
[![Join the chat at https://gitter.im/AArnott/PCLCrypto](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/AArnott/PCLCrypto?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![Issue Stats][pull-requests-img]][pull-requests-url] [![Issue Stats][issues-closed-img]][issues-closed-url]

### Features

 * Cryptographically strong random number generator 
 * Symmetric and asymmetric encryption and signatures 
 * Key derivation 
 * Native crypto performance for each platform. This provides a 2-100X perf improvement for RSA on Android and iOS.
 * Streaming encryption on WinRT, which goes beyond what the WinRT API itself offers (while still relying on the OS for the crypto implementation).
 * Support for multiple key formats (PKCS#1, PKCS#8, CAPI) on all platforms. 

The API is designed to be similar to that found on WinRT or the .NET Framework. However some code changes may be required if migrating to this library from platform-specific crypto.

### Installation

Add a dependency to this library into your project via the pre-built NuGet package: [PCLCrypto][4].

    Install-Package PclCrypto

Be sure to install the NuGet package into your Portable library as well as each platform-specific app that uses your portable library. If you're shipping your portable library on NuGet, be sure to specify PclCrypto as a NuGet package dependency of your own NuGet package and you're set.

Installing via NuGet is important because we use facade assemblies and platform-specific assemblies to allow your PCLs to access crypto that is normally available only to platform-specific libraries using a technique Paul Betts calls [Bait and switch PCLs][5]. NuGet handles all the magic for you. 

### Documentation

Online documentation is available on our [project wiki site][6].

### Donations

If you appreciate this library and/or find it useful, please consider [donating cash or bitcoins][8] to its author.

### FAQ

1. Can I trust the crypto implemented in this library?

   This library does not implement crypto. It merely provides PCL-compatible APIs to invoke crypto, and at runtime the crypto offered by the platform is invoked. So you should be able to trust the crypto available through this library almost as much as you can trust the crypto in the operating system you're already running on.

2. How does this differ from the cryptography offered to PCLs in the [PCLContrib][1] project?

 * PCLCrypto is focused on just delivering cryptography, with a good level of unit testing that runs on all supported platforms.
 * PCLCrypto follows the NuGet consumption patterns of [PCLStorage][3], which makes it very easy to consume from both PCLs and your platform-specific apps.
 * PCLCrypto is under active development. PCLContrib [hasn't been updated in a while][2].

### C# 6 Tip

One of the new features of C# 6 is [using static][9], which bring static members of static classes into scope. You can take advantage of this feature with PCLCrypto to simplify your code:

Before:

```csharp
...
using PCLCrypto;

class TwitterClient 
{
    private static string GenerateHash(string input, string key)
    {
        var mac = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        var keyMaterial = WinRTCrypto.CryptographicBuffer.ConvertStringToBinary(key, Encoding.UTF8);
        var cryptoKey = mac.CreateKey(keyMaterial);
        var hash = WinRTCrypto.CryptographicEngine.Sign(cryptoKey, WinRTCrypto.CryptographicBuffer.ConvertStringToBinary(input, Encoding.UTF8));
        return WinRTCrypto.CryptographicBuffer.EncodeToBase64String(hash);
    }
}
```

After:

```csharp
...
using PCLCrypto;
using static PCLCrypto.WinRTCrypto;

class TwitterClient 
{
  private static string GenerateHash(string input, string key)
  {
      var mac = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
      var keyMaterial = CryptographicBuffer.ConvertStringToBinary(key, Encoding.UTF8);
      var cryptoKey = mac.CreateKey(keyMaterial);
      var hash = CryptographicEngine.Sign(cryptoKey, CryptographicBuffer.ConvertStringToBinary(input, Encoding.UTF8));
      return CryptographicBuffer.EncodeToBase64String(hash);
  }
}
```

 [1]: https://pclcontrib.codeplex.com/
 [2]: https://pclcontrib.codeplex.com/SourceControl/list/changesets
 [3]: https://pclstorage.codeplex.com/
 [4]: http://nuget.org/packages/pclcrypto
 [5]: http://log.paulbetts.org/the-bait-and-switch-pcl-trick/
 [6]: https://github.com/aarnott/pclcrypto/wiki
 [7]: http://github.com/aarnott/pclcrypto
 [8]: https://www.coinbase.com/checkouts/b3affe1c4e7b7b60028c3efcce2b1931
 [9]: http://intellitect.com/static-using-statement-in-c-6-0/

[pull-requests-img]: http://www.issuestats.com/github/aarnott/pclcrypto/badge/pr
[pull-requests-url]: http://www.issuestats.com/github/aarnott/pclcrypto

[issues-closed-img]: http://www.issuestats.com/github/aarnott/pclcrypto/badge/issue
[issues-closed-url]: http://www.issuestats.com/github/aarnott/pclcrypto
