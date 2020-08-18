// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nerdbank.Streams;
using PCLCrypto;
using Xunit;

public class ECDiffieHellmanTests
{
    private static readonly byte[] SecretMessage = new byte[] { 0x1, 0x3, 0x2 };

    [SkippableFact(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    public void ImportExportPublicKey()
    {
        using (IECDiffieHellman? dh = NetFxCrypto.ECDiffieHellman.Create())
        {
            var publicKeyBytes = dh.PublicKey.ToByteArray();
            IECDiffieHellmanPublicKey? publicKey2 = NetFxCrypto.ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyBytes);
            Assert.NotNull(publicKey2);
            var publicKey2Bytes = publicKey2.ToByteArray();
            CollectionAssertEx.AreEqual(publicKeyBytes, publicKey2Bytes);
        }
    }

    [SkippableFact(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    public void KeySize()
    {
        const int expectedDefaultKeySize = 521;
        const int alternateLegalKeySize = 384;

        // Verify default key size
        using (IECDiffieHellman? dh = NetFxCrypto.ECDiffieHellman.Create())
        {
            Assert.Equal(expectedDefaultKeySize, dh.KeySize);
            int originalPublicKeyLength = dh.PublicKey.ToByteArray().Length * 8;

            // Verify effect of changing the key size.
            dh.KeySize = alternateLegalKeySize;
            Assert.Equal(alternateLegalKeySize, dh.KeySize);
            int alteredPublicKeyLength = dh.PublicKey.ToByteArray().Length * 8;
            Assert.True(alteredPublicKeyLength < originalPublicKeyLength);
        }
    }

    [SkippableFact(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    public void DeriveKeyMaterial()
    {
        IECDiffieHellman? dh1 = NetFxCrypto.ECDiffieHellman.Create();
        IECDiffieHellman? dh2 = NetFxCrypto.ECDiffieHellman.Create();

        byte[] secret1 = dh1.DeriveKeyMaterial(dh2.PublicKey);
        byte[] secret2 = dh2.DeriveKeyMaterial(dh1.PublicKey);

        CollectionAssertEx.AreEqual(secret1, secret2);
    }

    /// <summary>
    /// Demonstrates the end-to-end process of ECDSA authentication,
    /// ECDH key exchange, and AES symmetric encryption.
    /// </summary>
    /// <returns>A task for the async test.</returns>
    [SkippableFact(typeof(NotSupportedException), typeof(PlatformNotSupportedException))]
    public async Task PerfectForwardSecrecy()
    {
        CryptographicPublicKeyBlobType publicBlobType = CryptographicPublicKeyBlobType.BCryptPublicKey;
        CancellationToken cancellationToken = Debugger.IsAttached
            ? CancellationToken.None
            : new CancellationTokenSource(TimeSpan.FromSeconds(15)).Token;
        string pipeName = Guid.NewGuid().ToString();
        IAsymmetricKeyAlgorithmProvider? ecdsaAlgorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.EcdsaP256Sha256);

        (Stream, Stream) streams = FullDuplexStream.CreatePair();

        using ICryptographicKey? bob = ecdsaAlgorithm.CreateKeyPair(256);
        using ICryptographicKey? alice = ecdsaAlgorithm.CreateKeyPair(256);

        ICryptographicKey? bobPublic = ecdsaAlgorithm.ImportPublicKey(bob.ExportPublicKey(publicBlobType), publicBlobType);
        ICryptographicKey? alicePublic = ecdsaAlgorithm.ImportPublicKey(alice.ExportPublicKey(publicBlobType), publicBlobType);

        Task aliceRole = PlayAliceRoleAsync(alice, bobPublic, streams.Item1, cancellationToken);
        Task bobRole = PlayBobRoleAsync(bob, alicePublic, streams.Item2, cancellationToken);
        await Task.WhenAll(aliceRole, bobRole);
    }

    private static async Task WriteAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        using Substream s = stream.WriteSubstream();
        await s.WriteAsync(buffer, cancellationToken);
        await s.FlushAsync(cancellationToken);
    }

    private static async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        using Stream s = stream.ReadSubstream();

        byte[] buffer = new byte[5 * 1024];
        int totalBytesRead = 0;
        while (true)
        {
            int bytesRead = await s.ReadAsync(buffer.AsMemory(totalBytesRead, buffer.Length - totalBytesRead), cancellationToken);
            if (bytesRead == 0)
            {
                break;
            }

            totalBytesRead += bytesRead;
        }

        byte[] result = new byte[totalBytesRead];
        Array.Copy(buffer, result, totalBytesRead);
        return result;
    }

    private static async Task PlayAliceRoleAsync(ICryptographicKey ownSigningKey, ICryptographicKey othersSigningPublicKey, Stream channel, CancellationToken cancellationToken)
    {
        // Create ephemeral ECDH key pair, to prepare for the symmetric encryption key exchange.
        using (IECDiffieHellman? ecdhKeyPair = NetFxCrypto.ECDiffieHellman.Create())
        {
            // Alice receives Bob's ECDH public key and signature.
            byte[] bobPublicDH = await ReadAsync(channel, cancellationToken);
            byte[] bobSignedDH = await ReadAsync(channel, cancellationToken);

            // Alice verifies Bob's signature to be sure it's his key.
            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(othersSigningPublicKey, bobPublicDH, bobSignedDH));

            // Alice replies to Bob's public key by transmitting her own public key and signature.
            var ecdhPublicKey = ecdhKeyPair.PublicKey.ToByteArray();
            await WriteAsync(channel, ecdhPublicKey, cancellationToken);
            byte[] ecdhPublicKeySignature = WinRTCrypto.CryptographicEngine.Sign(ownSigningKey, ecdhPublicKey);
            await WriteAsync(channel, ecdhPublicKeySignature, cancellationToken);

            // Derive a shared secret with Bob by combining Alice's private key with Bob's public key.
            IECDiffieHellmanPublicKey? bobDHPK = NetFxCrypto.ECDiffieHellmanCngPublicKey.FromByteArray(bobPublicDH);
            byte[] encryptionKeyMaterial = ecdhKeyPair.DeriveKeyMaterial(bobDHPK);
            ICryptographicKey? symmetricEncryptionKey = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7)
                .CreateSymmetricKey(encryptionKeyMaterial);

            // Alice also adds a secret message.
            using (var aes = CryptoStream.WriteTo(channel, WinRTCrypto.CryptographicEngine.CreateEncryptor(symmetricEncryptionKey)))
            {
                await WriteAsync(aes, SecretMessage, cancellationToken);
            }

            channel.Dispose();
        }
    }

    private static async Task PlayBobRoleAsync(ICryptographicKey ownSigningKey, ICryptographicKey othersSigningPublicKey, Stream channel, CancellationToken cancellationToken)
    {
        // Create ephemeral ECDH key pair, to prepare for the symmetric encryption key exchange.
        using (IECDiffieHellman? ecdhKeyPair = NetFxCrypto.ECDiffieHellman.Create())
        {
            // Send the ephemeral ECDH public key to Alice.
            var ecdhPublicKey = ecdhKeyPair.PublicKey.ToByteArray();
            await WriteAsync(channel, ecdhPublicKey, cancellationToken);

            // Authenticate to Alice that this is really Bob's ephemeral public key.
            byte[] ecdhPublicKeySignature = WinRTCrypto.CryptographicEngine.Sign(ownSigningKey, ecdhPublicKey);
            await WriteAsync(channel, ecdhPublicKeySignature, cancellationToken);

            // Read Alice's reply. It consists of her own ephemeral public key and signature.
            byte[] alicePublicDH = await ReadAsync(channel, cancellationToken);
            byte[] aliceSignedDH = await ReadAsync(channel, cancellationToken);

            // Authenticate Alice's public key.
            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(othersSigningPublicKey, alicePublicDH, aliceSignedDH));

            // Deserialize Alice's public key and derive the shared secret from it.
            IECDiffieHellmanPublicKey? aliceDHPK = NetFxCrypto.ECDiffieHellmanCngPublicKey.FromByteArray(alicePublicDH);
            byte[] encryptionKeyMaterial = ecdhKeyPair.DeriveKeyMaterial(aliceDHPK);
            ICryptographicKey? encryptionKey = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7)
                .CreateSymmetricKey(encryptionKeyMaterial);

            // Bob reads Alice's secret message using the shared secret that both parties derived,
            // but never transmitted.
            using (var aes = CryptoStream.ReadFrom(channel, WinRTCrypto.CryptographicEngine.CreateDecryptor(encryptionKey)))
            {
                byte[] plaintext = await ReadAsync(aes, cancellationToken);

                // Assert that the plaintext is as it was expected to be.
                Assert.Equal(
                    Convert.ToBase64String(SecretMessage),
                    Convert.ToBase64String(plaintext));
            }

            channel.Dispose();
        }
    }
}
