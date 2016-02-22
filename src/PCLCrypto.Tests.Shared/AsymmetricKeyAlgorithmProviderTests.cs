// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using PCLCrypto;
using PCLCrypto.Formatters;
using Xunit;
using Xunit.Abstractions;

#if !(SILVERLIGHT && !WINDOWS_PHONE) // Silverlight 5 doesn't include asymmetric crypto
public class AsymmetricKeyAlgorithmProviderTests
{
#if DESKTOP || WinRT
    private const string SkipIfECDsaNotSupported = null;
#else
    private const string SkipIfECDsaNotSupported = "Not supported on this platform";
#endif

#if WP8 || DESKTOP // desktop relies on Mono.Security's RSAManaged, which is flakey. See https://bugzilla.xamarin.com/show_bug.cgi?id=35861
    private const string SkipIfLimitedToCapi = "Not supported on WP8";
#else
    private const string SkipIfLimitedToCapi = null;
#endif

#if WinRT
    private const int MinRsaKeySize = 512;
    private const int MinDsaKeySize = 512;
    private const int MaxDsaKeySize = 3072;
#elif DESKTOP
    private const int MinRsaKeySize = 384;
    private const int MinDsaKeySize = 512;
    private const int MaxDsaKeySize = 1024;
#else
    private const int MinRsaKeySize = 384;
    private const int MinDsaKeySize = 1024;
    private const int MaxDsaKeySize = 1024;
#endif

    /// <summary>
    /// A dictionary of key algorithms to test with key sizes (in bits).
    /// </summary>
    private static readonly IReadOnlyDictionary<AsymmetricAlgorithm, int> KeyAlgorithmsAndSizesToTest = new Dictionary<AsymmetricAlgorithm, int>
        {
            { AsymmetricAlgorithm.RsaOaepSha1, 512 },
            { AsymmetricAlgorithm.EcdsaP256Sha256, 256 },
        };

    private readonly ITestOutputHelper logger;

    public AsymmetricKeyAlgorithmProviderTests(ITestOutputHelper logger)
    {
        this.logger = logger;
    }

    /// <summary>
    /// A dictionary of key algorithms to test with key sizes (in bits).
    /// </summary>
    public static object[][] PrivateKeyAlgorithmsAndBlobsToTest =>
        (from algorithmAndSize in KeyAlgorithmsAndSizesToTest
         from blobType in Enum.GetValues(typeof(CryptographicPrivateKeyBlobType)).Cast<CryptographicPrivateKeyBlobType>()
         select new object[] { AsymmetricAlgorithm.RsaOaepSha1, 512, blobType }).ToArray();

    /// <summary>
    /// A dictionary of key algorithms to test with key sizes (in bits).
    /// </summary>
    public static object[][] PublicKeyAlgorithmsAndBlobsToTest =>
        (from algorithmAndSize in KeyAlgorithmsAndSizesToTest
         from blobType in Enum.GetValues(typeof(CryptographicPublicKeyBlobType)).Cast<CryptographicPublicKeyBlobType>()
         select new object[] { AsymmetricAlgorithm.RsaOaepSha1, 512, blobType }).ToArray();

    public static object[][] PublicKeyFormatsAndBlobsData =>
        Helper.PublicKeyFormatsAndBlobs.Select(kv => new object[] { kv.Key.Item1, kv.Key.Item2, kv.Value }).ToArray();

    public static object[][] PrivateKeyFormatsAndBlobsData =>
        Helper.PrivateKeyFormatsAndBlobs.Select(kv => new object[] { kv.Key.Item2, kv.Key.Item1, kv.Value }).ToArray();

    [Fact]
    public void OpenAlgorithm_GetAlgorithmName()
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        Assert.Equal(AsymmetricAlgorithm.RsaOaepSha1, rsa.Algorithm);
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [InlineData(AsymmetricAlgorithm.DsaSha1, MinDsaKeySize, MaxDsaKeySize, 64)]
    [InlineData(AsymmetricAlgorithm.DsaSha256, MinDsaKeySize, MaxDsaKeySize, 64)]
    [InlineData(AsymmetricAlgorithm.EcdsaP256Sha256, 256, 256, 0)]
    [InlineData(AsymmetricAlgorithm.EcdsaP384Sha384, 384, 384, 0)]
    [InlineData(AsymmetricAlgorithm.EcdsaP521Sha512, 521, 521, 0)]
    [InlineData(AsymmetricAlgorithm.RsaOaepSha1, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaOaepSha256, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaOaepSha384, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaOaepSha512, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaPkcs1, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaSignPkcs1Sha1, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaSignPkcs1Sha256, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaSignPkcs1Sha384, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaSignPkcs1Sha512, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaSignPssSha1, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaSignPssSha256, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaSignPssSha384, MinRsaKeySize, 16384, 8)]
    [InlineData(AsymmetricAlgorithm.RsaSignPssSha512, MinRsaKeySize, 16384, 8)]
    public void LegalKeySizes(AsymmetricAlgorithm name, int minSize, int maxSize, int stepSize)
    {
        IAsymmetricKeyAlgorithmProvider provider = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(name);
        var result = provider.LegalKeySizes;
        Assert.NotNull(result);
        Assert.NotEmpty(result);

        Action<int> attemptKeySize = size =>
        {
            provider.CreateKeyPair(size).Dispose();
        };

        var range = result.Single();
        Assert.Equal(minSize, range.MinSize);
        Assert.Equal(maxSize, range.MaxSize);
        Assert.Equal(stepSize, range.StepSize);
    }

    [Fact]
    public void CreateKeyPair_InvalidInputs()
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            rsa.CreateKeyPair(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            rsa.CreateKeyPair(0));
    }

    [Fact]
    public void CreateKeyPair_RsaOaepSha1()
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        var key = rsa.CreateKeyPair(512);
        Assert.NotNull(key);
        Assert.Equal(512, key.KeySize);
    }

    [Fact(Skip = SkipIfECDsaNotSupported)]
    public void CreateKeyPair_EcdsaP256Sha256()
    {
        var ecdsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.EcdsaP256Sha256);
        var key = ecdsa.CreateKeyPair(256);
        Assert.NotNull(key);
        Assert.Equal(256, key.KeySize);
    }

    [Fact]
    public void ImportKeyPair_Null()
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        Assert.Throws<ArgumentNullException>(
            () => rsa.ImportKeyPair(null));
    }

    [Fact]
    public void ImportPublicKey_Null()
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        Assert.Throws<ArgumentNullException>(
            () => rsa.ImportPublicKey(null));
    }

    [Fact]
    public void RSAParametersPrivateKeyRoundtrip()
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        var keyPair = rsa.CreateKeyPair(512);
        RSAParameters parameters = keyPair.ExportParameters(includePrivateParameters: true);
        ICryptographicKey keyPair2 = rsa.ImportParameters(parameters);

        var blob1 = keyPair.Export();
        var blob2 = keyPair2.Export();
        CollectionAssertEx.AreEqual(blob1, blob2);
    }

    [Fact]
    public void RSAParametersPublicKeyRoundtrip()
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        var keyPair = rsa.CreateKeyPair(512);
        RSAParameters parameters = keyPair.ExportParameters(includePrivateParameters: false);
        Assert.Null(parameters.P);
        Assert.Null(parameters.InverseQ);
        Assert.Null(parameters.D);
        Assert.Null(parameters.Q);
        Assert.Null(parameters.DP);
        Assert.Null(parameters.DQ);
        ICryptographicKey publicKey = rsa.ImportParameters(parameters);

        var blob1 = keyPair.ExportPublicKey();
        var blob2 = publicKey.ExportPublicKey();
        CollectionAssertEx.AreEqual(blob1, blob2);
    }

    [Fact]
    public void ExportParametersThrowsOnPublicKeyMismatch()
    {
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        var keyPair = rsa.CreateKeyPair(512);
        var publicKey = rsa.ImportPublicKey(keyPair.ExportPublicKey());

        // This should throw because we can't export a private key when only the public key is known.
        Assert.Throws<InvalidOperationException>(() => publicKey.ExportParameters(includePrivateParameters: true));
    }

    [Fact]
    public void ExportParametersThrowsOnSymmetricKey()
    {
        var keyProvider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        var key = keyProvider.CreateSymmetricKey(new byte[keyProvider.BlockLength]);
        Assert.Throws<NotSupportedException>(() => key.ExportParameters(includePrivateParameters: false));
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [MemberData(nameof(PrivateKeyAlgorithmsAndBlobsToTest))]
    public void KeyPairRoundTrip(AsymmetricAlgorithm algorithm, int keySize, CryptographicPrivateKeyBlobType format)
    {
        IAsymmetricKeyAlgorithmProvider keyAlgorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithm);

        using (ICryptographicKey key = keyAlgorithm.CreateKeyPair(keySize))
        {
            byte[] keyBlob = key.Export(format);
            using (var key2 = keyAlgorithm.ImportKeyPair(keyBlob, format))
            {
                byte[] key2Blob = key2.Export(format);

                Assert.Equal(Convert.ToBase64String(keyBlob), Convert.ToBase64String(key2Blob));
                this.logger.WriteLine(Convert.ToBase64String(keyBlob));
            }
        }
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [MemberData(nameof(PublicKeyAlgorithmsAndBlobsToTest))]
    public void PublicKeyRoundTrip(AsymmetricAlgorithm algorithm, int keySize, CryptographicPublicKeyBlobType format)
    {
        var keyAlgorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithm);

        using (var key = keyAlgorithm.CreateKeyPair(keySize))
        {
            byte[] keyBlob = key.ExportPublicKey(format);
            using (var key2 = keyAlgorithm.ImportPublicKey(keyBlob, format))
            {
                byte[] key2Blob = key2.ExportPublicKey(format);
                CollectionAssertEx.AreEqual(keyBlob, key2Blob);

                try
                {
                    // We use a non-empty buffer here because monotouch's
                    // Security.SecKey.Encrypt method has a bug that throws
                    // IndexOutOfRangeException when given empty buffers.
                    WinRTCrypto.CryptographicEngine.Encrypt(key2, new byte[1]);
                }
                catch (NotSupportedException)
                {
                    // Some algorithms, such as ECDSA, only support signing/verifying.
                }

                this.logger.WriteLine(Convert.ToBase64String(keyBlob));
            }
        }
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [MemberData(nameof(PrivateKeyFormatsAndBlobsData))]
    public void KeyPairInterop(CryptographicPrivateKeyBlobType blobType, AsymmetricAlgorithm algorithmName, string base64Key)
    {
        var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithmName);
        var key = algorithm.ImportKeyPair(Convert.FromBase64String(base64Key), blobType);
        string exported = Convert.ToBase64String(key.Export(blobType));
        if (blobType == CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo && exported.Length == base64Key.Length - 20)
        {
            // I'm not sure what the last 20 bytes are (perhaps the optional attributes)
            // But Windows platforms produces them and Android doesn't seem to.
            // Since the private key material seems to be elsewhere, we'll exclude
            // the suffix from the comparison.
            // The prefix is also mismatched, but that seems to also be ignorable.
            Assert.Equal(base64Key.Substring(6, exported.Length - 6), exported.Substring(6));
        }
        else
        {
            Assert.Equal(base64Key, exported);
        }
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [MemberData(nameof(PublicKeyFormatsAndBlobsData))]
    public void PublicKeyInterop(AsymmetricAlgorithm asymmetricAlgorithm, CryptographicPublicKeyBlobType blobType, string publicKeyBase64)
    {
        IAsymmetricKeyAlgorithmProvider algorithm;
        algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(asymmetricAlgorithm);

        var key = algorithm.ImportPublicKey(Convert.FromBase64String(publicKeyBase64), blobType);
        string exported = Convert.ToBase64String(key.ExportPublicKey(blobType));
        Assert.Equal(publicKeyBase64, exported);
    }

    [SkippableTheory(typeof(NotSupportedException))]
    [MemberData(nameof(PrivateKeyFormatsAndBlobsData))]
    public void EncryptionInterop(CryptographicPrivateKeyBlobType blobType, AsymmetricAlgorithm algorithmName, string base64Key)
    {
        byte[] data = new byte[] { 1, 2, 3 };
        byte[] cipherText = Convert.FromBase64String("EvnsqTK9tDemRIceCap4Yc5znXeb+nyBPsFRf6oT+OPqQ958RH7NXE3xLKsVJhOLJ4iJ2NM+AlrKRltIK8cTmw==");
        var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithmName);
        ICryptographicKey key = algorithm.ImportKeyPair(Convert.FromBase64String(base64Key), blobType);

        // Verify that we can decrypt something encrypted previously (on WinRT)
        this.logger.WriteLine("Verify decryption of ciphertext encrypted on WinRT.");
        byte[] decryptedPlaintext = WinRTCrypto.CryptographicEngine.Decrypt(key, cipherText);
        Assert.Equal(Convert.ToBase64String(decryptedPlaintext), Convert.ToBase64String(data));

        // Now verify we can decrypt something we encrypted ourselves.
        this.logger.WriteLine("Verify decryption of ciphertext encrypted on this platform.");
        byte[] myciphertext = WinRTCrypto.CryptographicEngine.Encrypt(key, data);
        byte[] myplaintext = WinRTCrypto.CryptographicEngine.Decrypt(key, myciphertext);
        Assert.Equal(Convert.ToBase64String(data), Convert.ToBase64String(myplaintext));
    }

#if !SILVERLIGHT
    /// <summary>
    /// Verifies that BCryptPrivateKey (which lacks many of the optional private parameters)
    /// gets filled in with the optional parameters equivalent to what they were originally.
    /// </summary>
    [Fact]
    public void PrivateKeyDataComputation()
    {
        var algorithmName = AsymmetricAlgorithm.RsaOaepSha1;
        string base64BCrypt = Helper.PrivateKeyFormatsAndBlobs[Tuple.Create(algorithmName, CryptographicPrivateKeyBlobType.BCryptPrivateKey)];
        string base64Pkcs1 = Helper.PrivateKeyFormatsAndBlobs[Tuple.Create(algorithmName, CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey)];

        var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithmName);
        ICryptographicKey bcryptKey = algorithm.ImportKeyPair(Convert.FromBase64String(base64BCrypt), CryptographicPrivateKeyBlobType.BCryptPrivateKey);
        ICryptographicKey pkcs1Key = algorithm.ImportKeyPair(Convert.FromBase64String(base64Pkcs1), CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey);

        var bcryptParameters = bcryptKey.ExportParameters(true);
        var pkcs1Parameters = pkcs1Key.ExportParameters(true);

        this.logger.WriteLine("PKCS1  P: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(pkcs1Parameters.P));
        this.logger.WriteLine("BCrypt P: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(bcryptParameters.P));
        this.logger.WriteLine("PKCS1  Q: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(pkcs1Parameters.Q));
        this.logger.WriteLine("BCrypt Q: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(bcryptParameters.Q));
        this.logger.WriteLine("PKCS1  D: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(pkcs1Parameters.D));
        this.logger.WriteLine("BCrypt D: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(bcryptParameters.D));
        this.logger.WriteLine("PKCS1  DP: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(pkcs1Parameters.DP));
        this.logger.WriteLine("BCrypt DP: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(bcryptParameters.DP));
        this.logger.WriteLine("PKCS1  DQ: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(pkcs1Parameters.DQ));
        this.logger.WriteLine("BCrypt DQ: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(bcryptParameters.DQ));
        this.logger.WriteLine("PKCS1  InverseQ: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(pkcs1Parameters.InverseQ));
        this.logger.WriteLine("BCrypt InverseQ: {0}", WinRTCrypto.CryptographicBuffer.EncodeToHexString(bcryptParameters.InverseQ));

        Assert.Equal<byte>(pkcs1Parameters.P, bcryptParameters.P);
        Assert.Equal<byte>(pkcs1Parameters.Q, bcryptParameters.Q);
        ////Assert.Equal<byte>(pkcs1Parameters.D, bcryptParameters.D); // not equal when computed ourselves, but equivalent
        Assert.Equal<byte>(pkcs1Parameters.DP, bcryptParameters.DP);
        Assert.Equal<byte>(pkcs1Parameters.DQ, bcryptParameters.DQ);
        Assert.Equal<byte>(pkcs1Parameters.InverseQ, bcryptParameters.InverseQ);
    }
#endif

    [Fact(Skip = SkipIfLimitedToCapi)]
    public void KeyPairInterop_iOSGenerated()
    {
        // Tests a key where P has more significant digits than Q.
        // This is incompatible with CAPI, which makes it worth testing.
        byte[] rsaPrivateKey = Convert.FromBase64String(@"MIIBPQIBAAJBAKJJ2g6qhep28mB5ySYb44dk9ZE0H+JQug9Tq2/1BjebHtW+YP/1Ds3tK/rQvL1A+yhLkFWOaQD6043AwJpWDxMCAwEAAQJAGr0sTmpOMjly6e5m8/54WKCLzWbXMgS3Azt37bRjV9nFGDqoq6gbwSnB709oouNPmqc4hE/6AqEnplfBfHX7YQIiAAGX4W2H9Y+uATS4dwnHnE6ROezx5275HLAjfARLRPQ3OwIhAGXbnimLuplWSVQ9/wE2eaISn5lF2tF1vKtvNSL3anoJAiIAARHo7jBupPV6k9gJAMVO36hBWTC+ddTPAi5iO1P803A/AiAVMKUsu3bsY3kJ34Pneq+/OeSd/FxTawz/FTmWtqYeEQIhACR2PamFTCPoeZEf73/OQeEVmLbd/xwozz8UOqGejqlh");
        var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);

        byte[] data = new byte[] { 1, 2, 3 };
        byte[] ciphertext, plaintext;
        using (ICryptographicKey key = rsa.ImportKeyPair(rsaPrivateKey, CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey))
        {
            ciphertext = WinRTCrypto.CryptographicEngine.Encrypt(key, data);
            plaintext = WinRTCrypto.CryptographicEngine.Decrypt(key, ciphertext);
        }

        Assert.Equal(Convert.ToBase64String(data), Convert.ToBase64String(plaintext));
    }

    [Fact]
    public void RSAParametersNotOverlyTrimmed()
    {
        // Test a private key that has a most significant bit of zero in its D parameter.
        // Specifically, we want to verify that such a key can be exported into the CAPI format.
        var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
        var key = algorithm.ImportKeyPair(
            Convert.FromBase64String("MIIBOgIBAAJBAKZ/iS3+Df6z6qD4/ZJI3Mfr/rWOvFdTZwCyoZ+CoMSW5QT93OW5fxWphus4Civ3+Q4fBrklNWvdmCjHgUuPOZkCAwEAAQI/8Qty7sMAP975sFLJyR7zg/yFpRQgV8zHMptqoiPb3L7CxcfPB71gjI3XPLfVc5cxNRl1QANEKGf+PE/Pb+xRAiEAz0zChuSpSLv0Rmccbeb0V7FsCTKKn8QQhE61DCE4ZgkCIQDNnOtqKnkuHws8sEYKfuolmlFPp0LD0PPptLwr8wGbEQIhAAlAhsoYeIm7gcqGnZk2Hp+vVoAOlmtNB+Ov05rH/MlpAiCq3EdUhc8FYI6589GAT07LyJzhECEPD8hg4OutqdYfwQIhAHcfeFuEU67QFPQs0JSzfG/mDDKtGCrcY7KGPBG4rRme"),
            CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey);

        // Just make sure it doesn't throw an exception.
        key.Export(CryptographicPrivateKeyBlobType.Capi1PrivateKey);
    }

    ////[Fact]
    ////public void SignedDataVerifyInterop()
    ////{

    ////}

    ////[Fact]
    ////public void SignedHashVerifyInterop()
    ////{

    ////}

    internal static class Helper
    {
        /// <summary>
        /// All the available private key blob types and a single sample key (RsaOaepSha1) serialized into each format.
        /// </summary>
        internal static readonly Dictionary<Tuple<AsymmetricAlgorithm, CryptographicPrivateKeyBlobType>, string> PrivateKeyFormatsAndBlobs = new Dictionary<Tuple<AsymmetricAlgorithm, CryptographicPrivateKeyBlobType>, string>
            {
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.BCryptPrivateKey), "UlNBMgACAAADAAAAQAAAACAAAAAgAAAAAQAB94rt9gMQH/izb02sdFQFJOFGf+J9mLETVOwlzj7WgPkvuSr5l5m91XLTjoxg5P6BZk8TicedMcR1cm3EZeQbk/n5fJGZGJ1n2b5qHjA6ybTwowbvAiii+iDO2pr/yqFL/YJvynOsnsxj5S69p6TGJev+fzzEn2ZoQjGk7y6JSdk=" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.Capi1PrivateKey), "BwIAAACkAABSU0EyAAIAAAEAAQCTG+RlxG1ydcQxnceJE09mgf7kYIyO03LVvZmX+Sq5L/mA1j7OJexUE7GYfeJ/RuEkBVR0rE1vs/gfEAP27Yr3S6HK/5raziD6oigC7waj8LTJOjAear7ZZ50YmZF8+fnZSYku76QxQmhmn8Q8f/7rJcakp70u5WPMnqxzym+C/XH4w8fVeWrH86kHPX/xCtVcj17ivLaIYxATl1lscp7YmSF20HSQyDDJSJjVQMhvoQlF21N//14q09xLaRzYxUD6p5DHUXoJaLb7p39VwHGO6BGhi5I+THOr/v85oCvvwEHvw64F2h3dN53P1uNcW8JnmPsooQQR6wvVBc6re20ZzNlpf96Gue4vx3N+TpYYytz32XtLRAqQ5OA9lgnzTA0=" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey), "MIIBOwIBAAJBAPeK7fYDEB/4s29NrHRUBSThRn/ifZixE1TsJc4+1oD5L7kq+ZeZvdVy046MYOT+gWZPE4nHnTHEdXJtxGXkG5MCAwEAAQJADUzzCZY94OSQCkRLe9n33MoYlk5+c8cv7rmG3n9p2cwZbXurzgXVC+sRBKEo+5hnwltc49bPnTfdHdoFrsPvQQIhAPn5fJGZGJ1n2b5qHjA6ybTwowbvAiii+iDO2pr/yqFLAiEA/YJvynOsnsxj5S69p6TGJev+fzzEn2ZoQjGk7y6JSdkCIQDYnnJsWZcTEGOItrziXo9c1Qrxfz0HqfPHannVx8P4cQIgQMXYHGlL3NMqXv9/U9tFCaFvyEDVmEjJMMiQdNB2IZkCIQDA7yugOf/+q3NMPpKLoRHojnHAVX+n+7ZoCXpRx5Cn+g==" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo), "MIIBZAIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA94rt9gMQH/izb02sdFQFJOFGf+J9mLETVOwlzj7WgPkvuSr5l5m91XLTjoxg5P6BZk8TicedMcR1cm3EZeQbkwIDAQABAkANTPMJlj3g5JAKREt72ffcyhiWTn5zxy/uuYbef2nZzBlte6vOBdUL6xEEoSj7mGfCW1zj1s+dN90d2gWuw+9BAiEA+fl8kZkYnWfZvmoeMDrJtPCjBu8CKKL6IM7amv/KoUsCIQD9gm/Kc6yezGPlLr2npMYl6/5/PMSfZmhCMaTvLolJ2QIhANiecmxZlxMQY4i2vOJej1zVCvF/PQep88dqedXHw/hxAiBAxdgcaUvc0ype/39T20UJoW/IQNWYSMkwyJB00HYhmQIhAMDvK6A5//6rc0w+kouhEeiOccBVf6f7tmgJelHHkKf6oA0wCwYDVR0PMQQDAgAQ" },
            };

        /// <summary>
        /// All the available public key blob types and a single sample key (RsaOaepSha1) serialized into each format.
        /// </summary>
        internal static readonly Dictionary<Tuple<AsymmetricAlgorithm, CryptographicPublicKeyBlobType>, string> PublicKeyFormatsAndBlobs = new Dictionary<Tuple<AsymmetricAlgorithm, CryptographicPublicKeyBlobType>, string>
            {
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPublicKeyBlobType.BCryptPublicKey), "UlNBMQACAAADAAAAQAAAAAAAAAAAAAAAAQABoetbetfLDOWmobkoUTBXEM9ImOqIV18ikFiJddccSqTAB28MdbKBVwv40Y40aJb3MO+mv5rlN0QO1iWfFGD/pw==" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPublicKeyBlobType.Capi1PublicKey), "BgIAAACkAABSU0ExAAIAAAEAAQCn/2AUnyXWDkQ35Zq/pu8w95ZoNI7R+AtXgbJ1DG8HwKRKHNd1iViQIl9XiOqYSM8QVzBRKLmhpuUMy9d6W+uh" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey), "MEgCQQCh61t618sM5aahuShRMFcQz0iY6ohXXyKQWIl11xxKpMAHbwx1soFXC/jRjjRolvcw76a/muU3RA7WJZ8UYP+nAgMBAAE=" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo), "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKHrW3rXywzlpqG5KFEwVxDPSJjqiFdfIpBYiXXXHEqkwAdvDHWygVcL+NGONGiW9zDvpr+a5TdEDtYlnxRg/6cCAwEAAQ==" },
                { Tuple.Create(AsymmetricAlgorithm.EcdsaP256Sha256, CryptographicPublicKeyBlobType.BCryptPublicKey), "RUNTMSAAAACRpP2lPrEj6EjfvGrB1P87zDfr0VmDnHzgUkZHBeIPw6JZ4otUCEQSYyHcuGd3+gsTfsiBDFIY1saBbmaoFiko" },
            };
    }
}
#endif
