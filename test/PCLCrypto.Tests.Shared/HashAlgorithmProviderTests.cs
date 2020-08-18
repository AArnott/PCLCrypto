// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;

public class HashAlgorithmProviderTests
{
    private readonly byte[] data = new byte[] { 0x1, 0x2, };

    private readonly string dataHash = @"DKYj4oVfLHXIQq0wL+gg5BtNGX0=";

    private readonly string dataHashTwice = @"7/byfLvaIq0efDyE+taJbZ8Y4JA=";

    [Fact]
    public void OpenAlgorithm()
    {
        IHashAlgorithmProvider provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
        Assert.NotNull(provider);
    }

    [Fact]
    public void Algorithm()
    {
        IHashAlgorithmProvider? provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
        Assert.Equal(HashAlgorithm.Sha1, provider.Algorithm);

        provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
        Assert.Equal(HashAlgorithm.Sha256, provider.Algorithm);
    }

    [Fact]
    public void HashData()
    {
        IHashAlgorithmProvider? hasher = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
        var hash = hasher.HashData(this.data);
        Assert.NotNull(hash);
        Assert.Equal(this.dataHash, Convert.ToBase64String(hash));
    }

    [Fact]
    public void HashData_InvalidInputs()
    {
        IHashAlgorithmProvider? hasher = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
        Assert.Throws<ArgumentNullException>(
            () => hasher.HashData(null!));
    }

    [Fact]
    public void HashLength()
    {
        IHashAlgorithmProvider? provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
        Assert.Equal(20, provider.HashLength);

        provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
        Assert.Equal(256 / 8, provider.HashLength);
    }

    [Fact]
    public void CreateHash()
    {
        IHashAlgorithmProvider? provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
        CryptographicHash? hasher = provider.CreateHash();
        Assert.NotNull(hasher);
    }

    [SkippableFact(typeof(PlatformNotSupportedException))]
    public void AppendAndGetValueAndReset()
    {
        IHashAlgorithmProvider? provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
        CryptographicHash? hasher = provider.CreateHash();
        hasher.Append(this.data);
        byte[] hash = hasher.GetValueAndReset();
        Assert.Equal(this.dataHash, Convert.ToBase64String(hash));

        // Hash again to verify that everything was properly reset.
        hasher.Append(this.data);
        hash = hasher.GetValueAndReset();
        Assert.Equal(this.dataHash, Convert.ToBase64String(hash));
    }

    [SkippableFact(typeof(PlatformNotSupportedException))]
    public void AppendTwice()
    {
        IHashAlgorithmProvider? provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
        CryptographicHash? hasher = provider.CreateHash();
        hasher.Append(this.data);
        hasher.Append(this.data);
        byte[] hash = hasher.GetValueAndReset();
        Assert.Equal(this.dataHashTwice, Convert.ToBase64String(hash));
    }

    [SkippableFact(typeof(PlatformNotSupportedException))]
    public void HashByCryptoStream()
    {
        IHashAlgorithmProvider? provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
        CryptographicHash? hasher = provider.CreateHash();
        using (var stream = new PCLCrypto.CryptoStream(Stream.Null, hasher, CryptoStreamMode.Write))
        {
            stream.Write(this.data, 0, this.data.Length);
        }

        Assert.Equal(this.dataHash, Convert.ToBase64String(hasher.GetValueAndReset()));
    }
}
