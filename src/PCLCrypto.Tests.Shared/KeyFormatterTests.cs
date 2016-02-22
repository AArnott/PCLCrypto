// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#if !SILVERLIGHT
namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using System.Text;
    using System.Threading.Tasks;
    using Formatters;
    using Xunit;
    using Xunit.Abstractions;

    public class KeyFormatterTests
    {
        private static Lazy<RSAParameters> rsaParameters;

        private readonly ITestOutputHelper logger;

        static KeyFormatterTests()
        {
            rsaParameters = new Lazy<RSAParameters>(() =>
            {
                var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
                using (var key = algorithm.CreateKeyPair(512))
                {
                    const CryptographicPrivateKeyBlobType keyBlobFormat = CryptographicPrivateKeyBlobType.BCryptFullPrivateKey;
                    byte[] bcryptNative = key.Export(keyBlobFormat);
                    var rsaParameters = KeyFormatter.GetFormatter(keyBlobFormat).Read(bcryptNative);
                    return rsaParameters;
                }
            });
        }

        public KeyFormatterTests(ITestOutputHelper logger)
        {
            this.logger = logger;
        }

        [SkippableTheory(typeof(NotSupportedException)), CombinatorialData]
        public void KeyFormatters_PrivateKeyRoundTrip(CryptographicPrivateKeyBlobType format)
        {
            this.logger.WriteLine("Generated RSA parameters:");
            this.LogRSAParameters(rsaParameters.Value, "  ");

            var formatter = KeyFormatter.GetFormatter(format);
            byte[] custom = formatter.Write(rsaParameters.Value);
            var rsaParametersRead = formatter.Read(custom);

            this.logger.WriteLine("Read RSA parameters:");
            this.LogRSAParameters(rsaParametersRead, "  ");

            Assert.Equal<byte>(rsaParameters.Value.Exponent, rsaParametersRead.Exponent);
            Assert.Equal<byte>(rsaParameters.Value.Modulus, rsaParametersRead.Modulus);

            Assert.Equal<byte>(rsaParameters.Value.P, rsaParametersRead.P);
            Assert.Equal<byte>(rsaParameters.Value.Q, rsaParametersRead.Q);

            if (format != CryptographicPrivateKeyBlobType.BCryptPrivateKey)
            {
                Assert.Equal<byte>(rsaParameters.Value.D, rsaParametersRead.D);
                Assert.Equal<byte>(rsaParameters.Value.DP, rsaParametersRead.DP);
                Assert.Equal<byte>(rsaParameters.Value.DQ, rsaParametersRead.DQ);
                Assert.Equal<byte>(rsaParameters.Value.InverseQ, rsaParametersRead.InverseQ);
            }
            else
            {
                // BCryptPrivateKey is lossy, by design.
                Assert.Null(rsaParametersRead.D);
                Assert.Null(rsaParametersRead.DP);
                Assert.Null(rsaParametersRead.DQ);
                Assert.Null(rsaParametersRead.InverseQ);
            }
        }

        [Theory, CombinatorialData]
        public void KeyFormatters_PublicKeyRoundTrip(CryptographicPublicKeyBlobType format)
        {
            var formatter = KeyFormatter.GetFormatter(format);
            byte[] custom = formatter.Write(rsaParameters.Value, includePrivateKey: false);
            var rsaParametersRead = formatter.Read(custom);

            Assert.Equal<byte>(rsaParameters.Value.Exponent, rsaParametersRead.Exponent);
            Assert.Equal<byte>(rsaParameters.Value.Modulus, rsaParametersRead.Modulus);

            Assert.Null(rsaParametersRead.D);
            Assert.Null(rsaParametersRead.P);
            Assert.Null(rsaParametersRead.Q);
            Assert.Null(rsaParametersRead.DP);
            Assert.Null(rsaParametersRead.DQ);
            Assert.Null(rsaParametersRead.InverseQ);
        }

        private void LogRSAParameters(RSAParameters parameters, string indent = "")
        {
            Action<string> logValue = name =>
            {
                byte[] value = (byte[])typeof(RSAParameters).GetTypeInfo().GetDeclaredField(name).GetValue(parameters);
                if (value != null)
                {
                    this.logger.WriteLine($"{indent}{name}: {WinRTCrypto.CryptographicBuffer.EncodeToHexString(value)}");
                }
            };
            logValue(nameof(RSAParameters.Modulus));
            logValue(nameof(RSAParameters.Exponent));
            logValue(nameof(RSAParameters.P));
            logValue(nameof(RSAParameters.D));
            logValue(nameof(RSAParameters.Q));
            logValue(nameof(RSAParameters.DP));
            logValue(nameof(RSAParameters.DQ));
            logValue(nameof(RSAParameters.InverseQ));
        }
    }
}
#endif
