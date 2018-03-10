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

    [SkippableTheory(typeof(NotSupportedException))]
    [InlineData(SymmetricAlgorithm.AesCbcPkcs7, 16)]
    [InlineData(SymmetricAlgorithm.AesEcb, 16)]
    public void BlockLength(SymmetricAlgorithm algorithm, int expectedBlockLength)
    {
        ISymmetricKeyAlgorithmProvider provider = WinRTCrypto.SymmetricKeyAlgorithmProvider
            .OpenAlgorithm(algorithm);
        Assert.NotNull(provider);
        Assert.Equal(expectedBlockLength, provider.BlockLength);
    }

    [SkippableTheory(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    [InlineData(SymmetricAlgorithmName.Aes, 128, 256, 64)]
#if NETCOREAPP1_0
    [InlineData(SymmetricAlgorithmName.Des, 128, 256, 64)]
#else
    [InlineData(SymmetricAlgorithmName.Des, 64, 64, 0)]
#endif
    [InlineData(SymmetricAlgorithmName.Rc4, 8, 512, 8)]
#if WinRT
    [InlineData(SymmetricAlgorithmName.Rc2, 16, 128, 8)]
    [InlineData(SymmetricAlgorithmName.TripleDes, 192, 192, 0)]
#elif NETCOREAPP1_0
    [InlineData(SymmetricAlgorithmName.Rc2, 128, 256, 64)]
    [InlineData(SymmetricAlgorithmName.TripleDes, 128, 256, 64)]
#else
    [InlineData(SymmetricAlgorithmName.Rc2, 40, 128, 8)]
    [InlineData(SymmetricAlgorithmName.TripleDes, 128, 192, 64)]
#endif
    public void LegalKeySizes(SymmetricAlgorithmName name, int minSize, int maxSize, int stepSize)
    {
        var blockMode = name.IsBlockCipher() ? SymmetricAlgorithmMode.Cbc : SymmetricAlgorithmMode.Streaming;
        var padding = name.IsBlockCipher() ? SymmetricAlgorithmPadding.PKCS7 : SymmetricAlgorithmPadding.None;
        ISymmetricKeyAlgorithmProvider provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(name, blockMode, padding);
        var result = provider.LegalKeySizes;
        Assert.NotNull(result);
        Assert.NotEmpty(result);

        var random = new Random();
        Action<int> attemptKeySize = size =>
        {
            var keyMaterial = new byte[size / 8];
            random.NextBytes(keyMaterial); // some algorithms check against weak keys (e.g. all zeros)
                provider.CreateSymmetricKey(keyMaterial).Dispose();
        };

        // Verify that each allegedly legal key size actually works.
        foreach (var item in result)
        {
            this.logger.WriteLine($"{item.MinSize}-{item.MaxSize} ({item.StepSize})");
            foreach (var keySize in item)
            {
                attemptKeySize(keySize);
            }

            // Also check the cases just off the edges of the range to see that they actually fail.
            // This ensures the returned values aren't too conservative.
#if false // WinRT actually doesn't throw when given keys of inappropriate size. Go figure.
            if (item.StepSize > 0)
            {
                if (item.MinSize - item.StepSize > 0)
                {
                    Assert.Throws<ArgumentException>(() => attemptKeySize(item.MinSize - item.StepSize));
                }

                if (item.MaxSize + item.StepSize > 0)
                {
                    Assert.Throws<ArgumentException>(() => attemptKeySize(item.MaxSize + item.StepSize));
                }
            }
#endif
        }

        var range = result.Single();
        Assert.Equal(minSize, range.MinSize);
        Assert.Equal(maxSize, range.MaxSize);
        Assert.Equal(stepSize, range.StepSize);
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
    [SkippableFact(typeof(PlatformNotSupportedException))]
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
