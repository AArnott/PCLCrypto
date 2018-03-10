// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PCLCrypto;
using PCLCrypto.Formatters;
using Xunit;
using RSAParameters = System.Security.Cryptography.RSAParameters;

public class Pkcs1KeyFormatterTests
{
    [Fact]
    public void Pkcs1DecodingTest()
    {
#pragma warning disable 0436
        // Initialize the "Known Good" RSAParameters.
        byte[] capi1Blob = Convert.FromBase64String(AsymmetricKeyAlgorithmProviderTests.Helper.PrivateKeyFormatsAndBlobs[Tuple.Create(PCLCrypto.AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.Capi1PrivateKey)]);
        var rsa = new RSACryptoServiceProvider();
        rsa.ImportCspBlob(capi1Blob);
        RSAParameters rsaCapi = rsa.ExportParameters(true);

        // Now load up the tested one.
        byte[] pkcs1KeyBlob = Convert.FromBase64String(AsymmetricKeyAlgorithmProviderTests.Helper.PrivateKeyFormatsAndBlobs[Tuple.Create(PCLCrypto.AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey)]);
        RSAParameters homeReadPkcs1 = KeyFormatter.ToPlatformParameters(KeyFormatter.Pkcs1.Read(pkcs1KeyBlob));
#pragma warning restore 0436
        Assert.Equal(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.Modulus), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.Modulus));
        Assert.Equal(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.Exponent), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.Exponent));
        Assert.Equal(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.D), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.D));
        Assert.Equal(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.P), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.P));
        Assert.Equal(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.Q), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.Q));
        Assert.Equal(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.DP), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.DP));
        Assert.Equal(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.DQ), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.DQ));
        Assert.Equal(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.InverseQ), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.InverseQ));
    }
}
