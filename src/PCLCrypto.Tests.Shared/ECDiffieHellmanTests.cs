#if !(SILVERLIGHT && !WINDOWS_PHONE) // Silverlight 5 doesn't include asymmetric crypto

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nerdbank;
using PCLCrypto;
using Xunit;

public class ECDiffieHellmanTests
{
#if DESKTOP || WinRT
    private const string SkipIfNotSupported = null;
#else
    private const string SkipIfNotSupported = "Not supported on this platform";
#endif

    private static readonly byte[] SecretMessage = new byte[] { 0x1, 0x3, 0x2 };

    [Fact(Skip = SkipIfNotSupported)]
    public void ImportExportPublicKey()
    {
        using (var dh = NetFxCrypto.ECDiffieHellman.Create())
        {
            var publicKeyBytes = dh.PublicKey.ToByteArray();
            var publicKey2 = NetFxCrypto.ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyBytes);
            Assert.NotNull(publicKey2);
            var publicKey2Bytes = publicKey2.ToByteArray();
            CollectionAssertEx.AreEqual(publicKeyBytes, publicKey2Bytes);
        }
    }

    [Fact(Skip = SkipIfNotSupported)]
    public void KeySize()
    {
        const int expectedDefaultKeySize = 521;
        const int alternateLegalKeySize = 384;

        // Verify default key size
        using (var dh = NetFxCrypto.ECDiffieHellman.Create())
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

    [Fact(Skip = SkipIfNotSupported)]
    public void DeriveKeyMaterial()
    {
        var dh1 = NetFxCrypto.ECDiffieHellman.Create();
        var dh2 = NetFxCrypto.ECDiffieHellman.Create();

        byte[] secret1 = dh1.DeriveKeyMaterial(dh2.PublicKey);
        byte[] secret2 = dh2.DeriveKeyMaterial(dh1.PublicKey);

        CollectionAssertEx.AreEqual(secret1, secret2);
    }

    /// <summary>
    /// Demonstrates the end-to-end process of ECDSA authentication,
    /// ECDH key exchange, and AES symmetric encryption.
    /// </summary>
    /// <returns>A task for the async test.</returns>
    [Fact(Skip = SkipIfNotSupported)]
    public async Task PerfectForwardSecrecy()
    {
        CryptographicPublicKeyBlobType publicBlobType = CryptographicPublicKeyBlobType.BCryptPublicKey;
        var cancellationToken = Debugger.IsAttached
            ? CancellationToken.None
            : new CancellationTokenSource(TimeSpan.FromSeconds(15)).Token;
        string pipeName = Guid.NewGuid().ToString();
        var ecdsaAlgorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.EcdsaP256Sha256);

        var streams = FullDuplexStream.CreateStreams();

        using (var bob = ecdsaAlgorithm.CreateKeyPair(256))
        using (var alice = ecdsaAlgorithm.CreateKeyPair(256))
        {
            var bobPublic = ecdsaAlgorithm.ImportPublicKey(bob.ExportPublicKey(publicBlobType), publicBlobType);
            var alicePublic = ecdsaAlgorithm.ImportPublicKey(alice.ExportPublicKey(publicBlobType), publicBlobType);

            Task aliceRole = this.PlayAliceRoleAsync(alice, bobPublic, streams.Item1, cancellationToken);
            Task bobRole = this.PlayBobRoleAsync(bob, alicePublic, streams.Item2, cancellationToken);
            await Task.WhenAll(aliceRole, bobRole);
        }
    }

    private static Task WriteAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        return stream.WriteAsync(buffer, 0, buffer.Length, cancellationToken);
    }

    private static async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[5 * 1024];
        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
        byte[] result = new byte[bytesRead];
        Array.Copy(buffer, result, bytesRead);
        return result;
    }

    private async Task PlayAliceRoleAsync(ICryptographicKey ownSigningKey, ICryptographicKey othersSigningPublicKey, Stream channel, CancellationToken cancellationToken)
    {
        // Create ephemeral ECDH key pair, to prepare for the symmetric encryption key exchange.
        using (var ecdhKeyPair = NetFxCrypto.ECDiffieHellman.Create())
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
            var bobDHPK = NetFxCrypto.ECDiffieHellmanCngPublicKey.FromByteArray(bobPublicDH);
            byte[] encryptionKeyMaterial = ecdhKeyPair.DeriveKeyMaterial(bobDHPK);
            var symmetricEncryptionKey = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7)
                .CreateSymmetricKey(encryptionKeyMaterial);

            // Alice also adds a secret message.
            using (var aes = CryptoStream.WriteTo(channel, WinRTCrypto.CryptographicEngine.CreateEncryptor(symmetricEncryptionKey)))
            {
                await aes.WriteAsync(SecretMessage, 0, SecretMessage.Length, cancellationToken);
            }

            channel.Dispose();
        }
    }

    private async Task PlayBobRoleAsync(ICryptographicKey ownSigningKey, ICryptographicKey othersSigningPublicKey, Stream channel, CancellationToken cancellationToken)
    {
        // Create ephemeral ECDH key pair, to prepare for the symmetric encryption key exchange.
        using (var ecdhKeyPair = NetFxCrypto.ECDiffieHellman.Create())
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
            var aliceDHPK = NetFxCrypto.ECDiffieHellmanCngPublicKey.FromByteArray(alicePublicDH);
            byte[] encryptionKeyMaterial = ecdhKeyPair.DeriveKeyMaterial(aliceDHPK);
            var encryptionKey = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7)
                .CreateSymmetricKey(encryptionKeyMaterial);

            // Bob reads Alice's secret message using the shared secret that both parties derived,
            // but never transmitted.
            using (var aes = CryptoStream.ReadFrom(channel, WinRTCrypto.CryptographicEngine.CreateDecryptor(encryptionKey)))
            {
                byte[] plaintext = await ReadAsync(aes, cancellationToken);

                // Assert that the plaintext is as it was expected to be.
                CollectionAssertEx.AreEqual(SecretMessage, plaintext);
            }

            channel.Dispose();
        }
    }
}

#endif
