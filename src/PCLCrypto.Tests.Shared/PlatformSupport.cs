// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;
using Xunit.Abstractions;

/// <summary>
/// A collection of tests used to audit support for specific features on various platforms.
/// </summary>
public class PlatformSupport
{
    private readonly ITestOutputHelper logger;

    public PlatformSupport(ITestOutputHelper logger)
    {
        this.logger = logger;
    }

    [SkippableTheory(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    [PairwiseData]
    public void SymmetricEncryption(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding)
    {
        Skip.If(mode.IsAuthenticated(), "This test is only for non-authenticated block modes.");
        bool badCombination = false;
        badCombination |= !mode.IsBlockCipher() && padding != SymmetricAlgorithmPadding.None; // Padding does not apply to streaming ciphers.
        badCombination |= name.IsBlockCipher() != mode.IsBlockCipher(); // Incompatible cipher and block mode.

        Func<ISymmetricKeyAlgorithmProvider> creator = () => WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(name, mode, padding);
        if (badCombination)
        {
            Assert.Throws<ArgumentException>(creator);
            this.logger.WriteLine("Expected exception thrown for invalid combination.");
            return;
        }

        var algorithm = creator();
        int keyLength = algorithm.LegalKeySizes.First().MinSize;
        var keyMaterial = WinRTCrypto.CryptographicBuffer.GenerateRandom(keyLength / 8);
        using (var key = algorithm.CreateSymmetricKey(keyMaterial))
        {
            var ciphertext = WinRTCrypto.CryptographicEngine.Encrypt(key, new byte[algorithm.BlockLength], null);
            Assert.NotEmpty(ciphertext);
        }
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [CombinatorialData]
    public void AsymmetricEncryption(AsymmetricAlgorithm algorithmName)
    {
        var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithmName);

        foreach (var keySize in algorithm.LegalKeySizes.SelectMany(k => k))
        {
            try
            {
                this.logger.WriteLine($"Testing {algorithmName} with {keySize} bit key.");
                using (var key = algorithm.CreateKeyPair(keySize))
                {
                }

                break;
            }
            catch (ArgumentException)
            {
                // WinRT does not provide legal key sizes, and doesn't allow small RSA keys.
                // It throws ArgumentException in this case. We can remove the skip on ArgumentException
                // after we switch WinRT over to using BCrypt directly.
                this.logger.WriteLine("Key size rejected. Please fix LegalKeySizes to report key sizes that actually work.");
            }
        }
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [CombinatorialData]
    public void Hash(HashAlgorithm hashAlgorithm)
    {
        var result = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(hashAlgorithm).HashData(new byte[5]);
        Assert.NotNull(result);
        Assert.NotEmpty(result);
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [CombinatorialData]
    public void PrivateKeyFormat(CryptographicPrivateKeyBlobType format)
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        var key = rsa.CreateKeyPair(512);
        byte[] serialized = key.Export(format);
        Assert.NotNull(serialized);
        Assert.NotEmpty(serialized);
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [CombinatorialData]
    public void PublicKeyFormat(CryptographicPublicKeyBlobType format)
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        var key = rsa.CreateKeyPair(512);
        byte[] serialized = key.ExportPublicKey(format);
        Assert.NotNull(serialized);
        Assert.NotEmpty(serialized);
    }

    [SkippableFact(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    public void KeyDerivation_Pbkdf2()
    {
        var provider = WinRTCrypto.KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithm.Pbkdf2Sha256);
        var originalKey = provider.CreateKey(Encoding.UTF8.GetBytes("my secret"));
        var salt = WinRTCrypto.CryptographicBuffer.GenerateRandom(32);
        const int iterationCount = 2;
        var parameters = WinRTCrypto.KeyDerivationParameters.BuildForPbkdf2(salt, iterationCount);

        const int desiredKeySize = 8;
        byte[] derivedKey = WinRTCrypto.CryptographicEngine.DeriveKeyMaterial(originalKey, parameters, desiredKeySize);
        Assert.Equal(desiredKeySize, derivedKey.Length);

        this.logger.WriteLine("Derived key: {0}", Convert.ToBase64String(derivedKey));
    }

    [SkippableFact(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    public void KeyDerivation_Sp800108()
    {
        var provider = WinRTCrypto.KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithm.Sp800108CtrHmacSha1);

        byte[] label = Encoding.UTF8.GetBytes("Purpose");
        byte[] context = { 1, 1, 0, 0, 0, 0, 0, 0 }; // a nonce
        var parameters = WinRTCrypto.KeyDerivationParameters.BuildForSP800108(label, context);

        const int desiredKeySize = 8;
        var originalKey = provider.CreateKey(Encoding.UTF8.GetBytes("my secret"));
        byte[] derivedKey = WinRTCrypto.CryptographicEngine.DeriveKeyMaterial(originalKey, parameters, desiredKeySize);
        Assert.Equal(desiredKeySize, derivedKey.Length);

        this.logger.WriteLine("Derived key: {0}", Convert.ToBase64String(derivedKey));
    }

    [SkippableFact(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    public void KeyDerivation_Sp80056a()
    {
        var provider = WinRTCrypto.KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithm.Sp80056aConcatMd5);

        byte[] algorithmId = Encoding.UTF8.GetBytes("Purpose");
        byte[] partyUInfo = Encoding.UTF8.GetBytes("Initiator public info");
        byte[] partyVInfo = Encoding.UTF8.GetBytes("Responder public info");
        byte[] suppPubInfo = Encoding.UTF8.GetBytes("Two party public info");
        byte[] suppPrivInfo = WinRTCrypto.CryptographicBuffer.GenerateRandom(32);
        var parameters = WinRTCrypto.KeyDerivationParameters.BuildForSP80056a(
            algorithmId,
            partyUInfo,
            partyVInfo,
            suppPubInfo,
            suppPrivInfo);

        const int desiredKeySize = 8;
        var originalKey = provider.CreateKey(Encoding.UTF8.GetBytes("my secret"));
        byte[] derivedKey = WinRTCrypto.CryptographicEngine.DeriveKeyMaterial(originalKey, parameters, desiredKeySize);
        Assert.Equal(desiredKeySize, derivedKey.Length);

        this.logger.WriteLine("Derived key: {0}", Convert.ToBase64String(derivedKey));
    }

    [SkippableTheory(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    [CombinatorialData]
    public void Mac(MacAlgorithm algorithm)
    {
        var provider = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(algorithm);
        var key = provider.CreateKey(WinRTCrypto.CryptographicBuffer.GenerateRandom(32));
        byte[] data = new byte[5];
        byte[] mac = WinRTCrypto.CryptographicEngine.Sign(key, data);
        Assert.Equal(provider.MacLength, mac.Length);
        Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(key, data, mac));
    }
}
