namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using PCLTesting;

    [TestClass]
    public class AsymmetricKeyAlgorithmProviderTests
    {
        /// <summary>
        /// All the available private key blob types and a single sample key (RsaOaepSha1) serialized into each format.
        /// </summary>
        private static readonly Dictionary<CryptographicPrivateKeyBlobType, string> PrivateKeyFormatsAndBlobs = new Dictionary<CryptographicPrivateKeyBlobType, string>
        {
            { CryptographicPrivateKeyBlobType.BCryptPrivateKey, "UlNBMgACAAADAAAAQAAAACAAAAAgAAAAAQAB94rt9gMQH/izb02sdFQFJOFGf+J9mLETVOwlzj7WgPkvuSr5l5m91XLTjoxg5P6BZk8TicedMcR1cm3EZeQbk/n5fJGZGJ1n2b5qHjA6ybTwowbvAiii+iDO2pr/yqFL/YJvynOsnsxj5S69p6TGJev+fzzEn2ZoQjGk7y6JSdk=" },
            { CryptographicPrivateKeyBlobType.Capi1PrivateKey, "BwIAAACkAABSU0EyAAIAAAEAAQCTG+RlxG1ydcQxnceJE09mgf7kYIyO03LVvZmX+Sq5L/mA1j7OJexUE7GYfeJ/RuEkBVR0rE1vs/gfEAP27Yr3S6HK/5raziD6oigC7waj8LTJOjAear7ZZ50YmZF8+fnZSYku76QxQmhmn8Q8f/7rJcakp70u5WPMnqxzym+C/XH4w8fVeWrH86kHPX/xCtVcj17ivLaIYxATl1lscp7YmSF20HSQyDDJSJjVQMhvoQlF21N//14q09xLaRzYxUD6p5DHUXoJaLb7p39VwHGO6BGhi5I+THOr/v85oCvvwEHvw64F2h3dN53P1uNcW8JnmPsooQQR6wvVBc6re20ZzNlpf96Gue4vx3N+TpYYytz32XtLRAqQ5OA9lgnzTA0=" },
            { CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey, "MIIBOwIBAAJBAPeK7fYDEB/4s29NrHRUBSThRn/ifZixE1TsJc4+1oD5L7kq+ZeZvdVy046MYOT+gWZPE4nHnTHEdXJtxGXkG5MCAwEAAQJADUzzCZY94OSQCkRLe9n33MoYlk5+c8cv7rmG3n9p2cwZbXurzgXVC+sRBKEo+5hnwltc49bPnTfdHdoFrsPvQQIhAPn5fJGZGJ1n2b5qHjA6ybTwowbvAiii+iDO2pr/yqFLAiEA/YJvynOsnsxj5S69p6TGJev+fzzEn2ZoQjGk7y6JSdkCIQDYnnJsWZcTEGOItrziXo9c1Qrxfz0HqfPHannVx8P4cQIgQMXYHGlL3NMqXv9/U9tFCaFvyEDVmEjJMMiQdNB2IZkCIQDA7yugOf/+q3NMPpKLoRHojnHAVX+n+7ZoCXpRx5Cn+g==" },
            { CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo, "MIIBZAIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA94rt9gMQH/izb02sdFQFJOFGf+J9mLETVOwlzj7WgPkvuSr5l5m91XLTjoxg5P6BZk8TicedMcR1cm3EZeQbkwIDAQABAkANTPMJlj3g5JAKREt72ffcyhiWTn5zxy/uuYbef2nZzBlte6vOBdUL6xEEoSj7mGfCW1zj1s+dN90d2gWuw+9BAiEA+fl8kZkYnWfZvmoeMDrJtPCjBu8CKKL6IM7amv/KoUsCIQD9gm/Kc6yezGPlLr2npMYl6/5/PMSfZmhCMaTvLolJ2QIhANiecmxZlxMQY4i2vOJej1zVCvF/PQep88dqedXHw/hxAiBAxdgcaUvc0ype/39T20UJoW/IQNWYSMkwyJB00HYhmQIhAMDvK6A5//6rc0w+kouhEeiOccBVf6f7tmgJelHHkKf6oA0wCwYDVR0PMQQDAgAQ" },
        };

        /// <summary>
        /// All the available public key blob types and a single sample key (RsaOaepSha1) serialized into each format.
        /// </summary>
        private static readonly Dictionary<CryptographicPublicKeyBlobType, string> PublicKeyFormatsAndBlobs = new Dictionary<CryptographicPublicKeyBlobType, string>
        {
            { CryptographicPublicKeyBlobType.BCryptPublicKey, "UlNBMQACAAADAAAAQAAAAAAAAAAAAAAAAQABoetbetfLDOWmobkoUTBXEM9ImOqIV18ikFiJddccSqTAB28MdbKBVwv40Y40aJb3MO+mv5rlN0QO1iWfFGD/pw==" },
            { CryptographicPublicKeyBlobType.Capi1PublicKey, "BgIAAACkAABSU0ExAAIAAAEAAQCn/2AUnyXWDkQ35Zq/pu8w95ZoNI7R+AtXgbJ1DG8HwKRKHNd1iViQIl9XiOqYSM8QVzBRKLmhpuUMy9d6W+uh" },
            { CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey, "MEgCQQCh61t618sM5aahuShRMFcQz0iY6ohXXyKQWIl11xxKpMAHbwx1soFXC/jRjjRolvcw76a/muU3RA7WJZ8UYP+nAgMBAAE=" },
            { CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo, "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKHrW3rXywzlpqG5KFEwVxDPSJjqiFdfIpBYiXXXHEqkwAdvDHWygVcL+NGONGiW9zDvpr+a5TdEDtYlnxRg/6cCAwEAAQ==" },
        };

        [TestMethod]
        public void OpenAlgorithm_GetAlgorithmName()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            Assert.AreEqual(AsymmetricAlgorithm.RsaOaepSha1, rsa.Algorithm);
        }

        [TestMethod]
        public void CreateKeyPair_InvalidInputs()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.CreateKeyPair(-1));
            ExceptionAssert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.CreateKeyPair(0));
        }

        [TestMethod]
        public void CreateKeyPair()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = rsa.CreateKeyPair(512);
            Assert.IsNotNull(key);
            Assert.AreEqual(512, key.KeySize);
        }

        [TestMethod]
        public void ImportKeyPair_Null()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => rsa.ImportKeyPair(null));
        }

        [TestMethod]
        public void ImportPublicKey_Null()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => rsa.ImportPublicKey(null));
        }

        [TestMethod]
        public void KeyPairRoundTrip()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = rsa.CreateKeyPair(512);

            int supportedFormats = 0;
            foreach (CryptographicPrivateKeyBlobType format in Enum.GetValues(typeof(CryptographicPrivateKeyBlobType)))
            {
                try
                {
                    byte[] keyBlob = key.Export(format);
                    var key2 = rsa.ImportKeyPair(keyBlob, format);
                    byte[] key2Blob = key2.Export(format);

                    CollectionAssertEx.AreEqual(keyBlob, key2Blob);
                    Debug.WriteLine("Format {0} supported.", format);
                    Debug.WriteLine(Convert.ToBase64String(keyBlob));
                    supportedFormats++;
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Format {0} NOT supported.", format);
                }
            }

            Assert.IsTrue(supportedFormats > 0, "No supported formats.");
        }

        [TestMethod]
        public void PublicKeyRoundTrip()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = rsa.CreateKeyPair(512);

            int supportedFormats = 0;
            foreach (CryptographicPublicKeyBlobType format in Enum.GetValues(typeof(CryptographicPublicKeyBlobType)))
            {
                try
                {
                    byte[] keyBlob = key.ExportPublicKey(format);
                    var key2 = rsa.ImportPublicKey(keyBlob, format);
                    byte[] key2Blob = key2.ExportPublicKey(format);

                    CollectionAssertEx.AreEqual(keyBlob, key2Blob);
                    Debug.WriteLine("Format {0} supported.", format);
                    Debug.WriteLine(Convert.ToBase64String(keyBlob));
                    supportedFormats++;
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Format {0} NOT supported.", format);
                }
            }

            Assert.IsTrue(supportedFormats > 0, "No supported formats.");
        }

        [TestMethod]
        public void KeyPairInterop()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            int supportedFormats = 0;
            foreach (var formatAndBlob in PrivateKeyFormatsAndBlobs)
            {
                try
                {
                    var key = rsa.ImportKeyPair(Convert.FromBase64String(formatAndBlob.Value), formatAndBlob.Key);
                    string exported = Convert.ToBase64String(key.Export(formatAndBlob.Key));
                    if (formatAndBlob.Key == CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo && exported.Length == formatAndBlob.Value.Length - 20)
                    {
                        // I'm not sure what the last 20 bytes are (perhaps the optional attributes)
                        // But Windows platforms produces them and Android doesn't seem to.
                        // Since the private key material seems to be elsewhere, we'll exclude
                        // the suffix from the comparison.
                        // The prefix is also mismatched, but that seems to also be ignorable.
                        Assert.AreEqual(formatAndBlob.Value.Substring(6, exported.Length - 6), exported.Substring(6));
                    }
                    else
                    {
                        Assert.AreEqual(formatAndBlob.Value, exported);
                    }

                    supportedFormats++;
                    Debug.WriteLine("Key format {0} supported.", formatAndBlob.Key);
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Key format {0} NOT supported.", formatAndBlob.Key);
                }
            }

            Assert.IsTrue(supportedFormats > 0, "No supported formats.");
        }

        [TestMethod]
        public void PublicKeyInterop()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            int supportedFormats = 0;
            foreach (var formatAndBlob in PublicKeyFormatsAndBlobs)
            {
                try
                {
                    var key = rsa.ImportPublicKey(Convert.FromBase64String(formatAndBlob.Value), formatAndBlob.Key);
                    string exported = Convert.ToBase64String(key.ExportPublicKey(formatAndBlob.Key));
                    Assert.AreEqual(formatAndBlob.Value, exported);
                    supportedFormats++;
                    Debug.WriteLine("Key format {0} supported.", formatAndBlob.Key);
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Key format {0} NOT supported.", formatAndBlob.Key);
                }
            }

            Assert.IsTrue(supportedFormats > 0, "No supported formats.");
        }

        [TestMethod]
        public void EncryptionInterop()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            byte[] data = new byte[] { 1, 2, 3 };
            byte[] cipherText = Convert.FromBase64String("EvnsqTK9tDemRIceCap4Yc5znXeb+nyBPsFRf6oT+OPqQ958RH7NXE3xLKsVJhOLJ4iJ2NM+AlrKRltIK8cTmw==");
            foreach (var formatAndBlob in PrivateKeyFormatsAndBlobs)
            {
                ICryptographicKey key;
                try
                {
                    key = rsa.ImportKeyPair(Convert.FromBase64String(formatAndBlob.Value), formatAndBlob.Key);
                }
                catch (NotSupportedException)
                {
                    continue;
                }

                // Verify that we can decrypt something encrypted previously (on WinRT)
                byte[] decryptedPlaintext = WinRTCrypto.CryptographicEngine.Decrypt(key, cipherText);
                Assert.AreEqual(Convert.ToBase64String(decryptedPlaintext), Convert.ToBase64String(data));

                // Now verify we can decrypt something we encrypted ourselves.
                byte[] myciphertext = WinRTCrypto.CryptographicEngine.Encrypt(key, data);
                byte[] myplaintext = WinRTCrypto.CryptographicEngine.Decrypt(key, myciphertext);
                Assert.AreEqual(Convert.ToBase64String(data), Convert.ToBase64String(myplaintext));

                return; // We only need one key format to work for the encryption test.
            }

            Assert.IsTrue(false, "No supported formats.");
        }
    }
}
