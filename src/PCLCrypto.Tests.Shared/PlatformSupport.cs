// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;
using PCLCrypto;
using Xunit;

public class PlatformSupport
{
    [SkippableTheory(typeof(NotSupportedException))]
    [CombinatorialData]
    public void SymmetricEncryption(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding)
    {
        using (var algorithm = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(name, mode, padding))
        {
            int keyLength = algorithm.BlockLength;
            var keyMaterial = WinRTCrypto.CryptographicBuffer.GenerateRandom(keyLength);
            using (var key = algorithm.CreateSymmetricKey(keyMaterial))
            {
                var ciphertext = WinRTCrypto.CryptographicEngine.Encrypt(key, new byte[algorithm.BlockLength], null);
                Assert.Equal(algorithm.BlockLength, ciphertext.Length);
            }
        }
    }
}
