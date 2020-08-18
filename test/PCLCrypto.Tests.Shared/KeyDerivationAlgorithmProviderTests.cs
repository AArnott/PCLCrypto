// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;
using Xunit.Abstractions;

public class KeyDerivationAlgorithmProviderTests
{
    private readonly byte[] originalKey = new byte[] { 0x1, 0x2, 0x3, 0x5 };
    private readonly byte[] salt = new byte[8];
    private readonly int iterations = 100;

    private readonly ITestOutputHelper logger;

    public KeyDerivationAlgorithmProviderTests(ITestOutputHelper logger)
    {
        this.logger = logger;
    }

    [Fact]
    public void OpenAlgorithm()
    {
        IKeyDerivationAlgorithmProvider? algorithm = WinRTCrypto.KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithm.Pbkdf2Sha1);
        Assert.NotNull(algorithm);
    }

    [Fact]
    public void Algorithm()
    {
        IKeyDerivationAlgorithmProvider? algorithm = WinRTCrypto.KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithm.Pbkdf2Sha1);
        Assert.Equal(KeyDerivationAlgorithm.Pbkdf2Sha1, algorithm.Algorithm);

        algorithm = WinRTCrypto.KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithm.Pbkdf2Md5);
        Assert.Equal(KeyDerivationAlgorithm.Pbkdf2Md5, algorithm.Algorithm);
    }

    [Fact]
    public void CreateKey_InvalidInputs()
    {
        IKeyDerivationAlgorithmProvider? algorithm = WinRTCrypto.KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithm.Pbkdf2Sha1);
        Assert.Throws<ArgumentNullException>(
            () => algorithm.CreateKey(null!));
    }

    [Theory]
    [InlineData(KeyDerivationAlgorithm.Pbkdf2Sha1, "3HWzwI225INl7y6+G9Jv7Af8UGE=")]
    [InlineData(KeyDerivationAlgorithm.Pbkdf2Sha256, "t420R6yC8H2CDK/0sSGmwKHLooM=")]
    public void CreateKey(KeyDerivationAlgorithm algorithmName, string result)
    {
        this.logger.WriteLine("Testing algorithm: {0}", algorithmName);
        IKeyDerivationAlgorithmProvider? algorithm = WinRTCrypto.KeyDerivationAlgorithmProvider.OpenAlgorithm(algorithmName);
        ICryptographicKey key = algorithm.CreateKey(this.originalKey);
        Assert.NotNull(key);
        Assert.Equal(this.originalKey.Length * 8, key.KeySize);

        IKeyDerivationParameters parameters = WinRTCrypto.KeyDerivationParameters.BuildForPbkdf2(this.salt, this.iterations);
        Assert.Equal(this.iterations, parameters.IterationCount);
        CollectionAssertEx.AreEqual(this.salt, parameters.KdfGenericBinary);

        try
        {
            byte[] keyMaterial = WinRTCrypto.CryptographicEngine.DeriveKeyMaterial(key, parameters, 20);
            Assert.Equal(result, Convert.ToBase64String(keyMaterial));
        }
        catch (NotSupportedException)
        {
            this.logger.WriteLine(" - Not supported on this platform");
        }
    }
}
