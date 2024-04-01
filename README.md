# PCLCrypto

## ⚠️ Archive notice ⚠️

PCLCrypto hasn't been developed for years.
It was written when the .NET runtime that shipped across mobile platforms lacked the crypto that .NET Framework had.
That hole has long since been filled.
.NET has evolved to include scenarios (e.g. trimming) that this library hasn't been tested with nor supports.
I suggest you switch from PCLCrypto to the standard .NET APIs.

## Summary

PCLCrypto provides cryptographic APIs over algorithms implemented by the platform, including exposing them to portable libraries.
PCLCrypto does not implement any crypto directly, thus making this library a good choice for applications that require the assurance of high quality crypto implementations that can most reliably be found within the operating system itself or hardware.

[![Build Status](https://dev.azure.com/andrewarnott/OSS/_apis/build/status/PCLCrypto?branchName=main)](https://dev.azure.com/andrewarnott/OSS/_build/latest?definitionId=45&branchName=main)
[![NuGet package](https://buildstats.info/nuget/PCLCrypto?includePreReleases=true)](https://nuget.org/packages/PCLCrypto)
[![Join the chat at https://gitter.im/AArnott/PCLCrypto](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/AArnott/PCLCrypto?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Features

* Cryptographically strong random number generator
* Symmetric and asymmetric encryption and signatures
* Key derivation
* Native crypto performance for each platform. This provides a 2-100X perf improvement for RSA on Android and iOS.
* Streaming encryption on UAP, which goes beyond what the WinRT API itself offers (while still relying on the OS for the crypto implementation).
* Support for multiple key formats (PKCS#1, PKCS#8, CAPI) on all platforms.

The API is designed to be similar to that found on WinRT or the .NET Framework. However some code changes may be required if migrating to this library from platform-specific crypto.

### Installation

Add a dependency to this library into your project via the `PCLCrypto` NuGet package:

[![NuGet package](https://buildstats.info/nuget/PCLCrypto?includePreReleases=true)](https://nuget.org/packages/PCLCrypto)

When using `packages.config`, you must be sure to install this package into each app project as well as any libraries in order to consume the right PCLCrypto.dll runtime library for the target platform.
If you use `PackageReference` (preferred), this happens automatically.

Installing via NuGet is important because we use facade assemblies and platform-specific assemblies to allow your portable libraries to access crypto that is normally available only to platform-specific libraries using a technique Paul Betts calls [Bait and switch PCLs][BaitAndSwitch]. NuGet handles all the magic for you.

### Documentation

Online documentation is available on our [project wiki site][Wiki].

### Donations

If you appreciate this library and/or find it useful, please consider becoming a [GitHub sponsor for its author](https://github.com/sponsors/AArnott)
or donating bitcoins to `1NC4k82nNev5Cz7ESBfaohbGsC6TKyjKvX` or any other mechanism shown on [their Keybase profile][Keybase].

### FAQ

1. Can I trust the crypto implemented in this library?

   This library does not implement crypto. It merely provides .NET Standard-compatible APIs to invoke crypto, and at runtime the crypto offered by the platform is invoked. So you should be able to trust the crypto available through this library almost as much as you can trust the crypto in the operating system your application is already running on.

### C# 6 Tip

One of the new features of C# 6 is [using static][StaticUsing], which bring static members of static classes into scope. You can take advantage of this feature with PCLCrypto to simplify your code:

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

 [BaitAndSwitch]: http://log.paulbetts.org/the-bait-and-switch-pcl-trick/
 [Wiki]: https://github.com/aarnott/pclcrypto/wiki
 [StaticUsing]: http://intellitect.com/static-using-statement-in-c-6-0/
 [Keybase]: https://keybase.io/aarnott
