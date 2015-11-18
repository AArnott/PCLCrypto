// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;

public class MacAlgorithmProviderTests
{
    private readonly byte[] keyMaterial = new byte[] { 0x1, 0x23, 0x15 };

    private readonly byte[] data = Encoding.UTF8.GetBytes("hello");

    private readonly string macBase64 = "WJJtHvbUeB7r1ORCnZjxXxK78Nk=";

    [Fact]
    public void OpenAlgorithm()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.AesCmac);
        Assert.NotNull(algorithm);
    }

    [Fact]
    public void Algorithm()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.AesCmac);
        Assert.Equal(MacAlgorithm.AesCmac, algorithm.Algorithm);

        algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        Assert.Equal(MacAlgorithm.HmacSha1, algorithm.Algorithm);
    }

    [Fact]
    public void MacLength()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        Assert.Equal(20, algorithm.MacLength);

        algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha256);
        Assert.Equal(256 / 8, algorithm.MacLength);
    }

    [Fact]
    public void CreateHash_InvalidInputs()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        Assert.Throws<ArgumentNullException>(
            () => algorithm.CreateHash(null));
    }

    [Fact]
    public void CreateHash()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        CryptographicHash hasher = algorithm.CreateHash(this.keyMaterial);
        Assert.NotNull(hasher);
        hasher.Append(this.data);
        byte[] mac = hasher.GetValueAndReset();
        Assert.Equal(this.macBase64, Convert.ToBase64String(mac));
    }

    [Fact]
    public void CreateKey_InvalidInputs()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        Assert.Throws<ArgumentNullException>(
            () => algorithm.CreateKey(null));
    }

    [Fact]
    public void CreateKey_NotExportable()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        ICryptographicKey key = algorithm.CreateKey(this.keyMaterial);
        Assert.Throws<NotSupportedException>(
            () => key.Export());
        Assert.Throws<NotSupportedException>(
            () => key.ExportPublicKey());
    }

    [Fact]
    public void CreateKey()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        ICryptographicKey key = algorithm.CreateKey(this.keyMaterial);
        Assert.NotNull(key);
        Assert.Equal(this.keyMaterial.Length, key.KeySize);
        byte[] mac = WinRTCrypto.CryptographicEngine.Sign(key, this.data);
        Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(key, this.data, mac));
        Assert.Equal(this.macBase64, Convert.ToBase64String(mac));
    }

    [Fact]
    public void HashByCryptoStream()
    {
        var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
        var hasher = algorithm.CreateHash(this.keyMaterial);
        using (var stream = new PCLCrypto.CryptoStream(Stream.Null, hasher, CryptoStreamMode.Write))
        {
            stream.Write(this.data, 0, this.data.Length);
        }

        Assert.Equal(this.macBase64, Convert.ToBase64String(hasher.GetValueAndReset()));
    }
}
