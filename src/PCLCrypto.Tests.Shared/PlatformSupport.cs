// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;

/// <summary>
/// A collection of tests used to audit support for specific features on various platforms.
/// </summary>
public class PlatformSupport
{
    [SkippableTheory(typeof(NotSupportedException))]
    [CombinatorialData]
    public void SymmetricEncryption(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding)
    {
        using (var algorithm = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(name, mode, padding))
        {
            int keyLength = algorithm.LegalKeySizes.First().MinSize;
            var keyMaterial = WinRTCrypto.CryptographicBuffer.GenerateRandom(keyLength / 8);
            using (var key = algorithm.CreateSymmetricKey(keyMaterial))
            {
                var ciphertext = WinRTCrypto.CryptographicEngine.Encrypt(key, new byte[algorithm.BlockLength], null);
                Assert.NotEqual(0, ciphertext.Length);
            }
        }
    }
}
