// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;
using Xunit.Abstractions;

public class SymmetricKeyAlgorithmProviderTests
{
    private readonly byte[] keyMaterial = new byte[16] { 0x2, 0x5, 0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, };

    private readonly ITestOutputHelper logger;

    public SymmetricKeyAlgorithmProviderTests(ITestOutputHelper logger)
    {
        this.logger = logger;
    }

    [Fact]
    public void BlockLength()
    {
        ISymmetricKeyAlgorithmProvider provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        Assert.NotNull(provider);
        Assert.Equal(16, provider.BlockLength);
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [InlineData(SymmetricAlgorithmName.Aes, 128, 256, 64)]
    [InlineData(SymmetricAlgorithmName.Des, 64, 64, 0)]
    [InlineData(SymmetricAlgorithmName.Rc4, 8, 512, 8)]
#if DESKTOP
    [InlineData(SymmetricAlgorithmName.Rc2, 40, 128, 8)]
    [InlineData(SymmetricAlgorithmName.TripleDes, 128, 192, 64)]
#else
    [InlineData(SymmetricAlgorithmName.Rc2, 16, 128, 8)]
    [InlineData(SymmetricAlgorithmName.TripleDes, 192, 192, 0)]
#endif
    public void LegalKeySizes(SymmetricAlgorithmName name, int minSize, int maxSize, int stepSize)
    {
        var blockMode = name.IsBlockCipher() ? SymmetricAlgorithmMode.Cbc : SymmetricAlgorithmMode.Streaming;
        using (ISymmetricKeyAlgorithmProvider provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(name, blockMode, SymmetricAlgorithmPadding.None))
        {
            var result = provider.LegalKeySizes;
            Assert.NotNull(result);
            Assert.NotEmpty(result);
            foreach (var item in result)
            {
                this.logger.WriteLine($"{item.MinSize}-{item.MaxSize} ({item.StepSize})");
            }

            var range = result.Single();
            Assert.Equal(minSize, range.MinSize);
            Assert.Equal(maxSize, range.MaxSize);
            Assert.Equal(stepSize, range.StepSize);
        }
    }

    [Fact]
    public void CreateSymmetricKey_InvalidInputs()
    {
        var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        Assert.Throws<ArgumentNullException>(
            () => provider.CreateSymmetricKey(null));
        Assert.Throws<ArgumentException>(
            () => provider.CreateSymmetricKey(new byte[0]));
        Assert.Throws<ArgumentException>(
            () =>
            {
                var key = provider.CreateSymmetricKey(new byte[4]);
                WinRTCrypto.CryptographicEngine.Encrypt(key, new byte[] { 1, 2, 3 });
            });
    }

    [Fact]
    public void CreateSymmetricKey_AesCbcPkcs7()
    {
        this.CreateSymmetricKeyHelper(SymmetricAlgorithm.AesCbcPkcs7);
    }

#if !(SILVERLIGHT || __IOS__)
    [Fact]
    public void CreateSymmetricKey_AesEcbPkcs7()
    {
        this.CreateSymmetricKeyHelper(SymmetricAlgorithm.AesEcbPkcs7);
    }
#endif

    [Fact]
    public void CreateSymmetricKey_Export()
    {
        var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
        Assert.Throws<NotSupportedException>(
            () => key.Export());
    }

    [Fact]
    public void CreateSymmetricKey_ExportPublicKey()
    {
        var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
        Assert.Throws<NotSupportedException>(
            () => key.ExportPublicKey());
    }

    private void CreateSymmetricKeyHelper(SymmetricAlgorithm algorithm)
    {
        var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithm);
        ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
        Assert.NotNull(key);
        Assert.Equal(this.keyMaterial.Length * 8, key.KeySize);
    }
}
