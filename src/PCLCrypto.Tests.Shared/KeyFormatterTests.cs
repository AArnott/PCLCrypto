// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#if !SILVERLIGHT
namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Formatters;
    using Xunit;

    public class KeyFormatterTests
    {
        private static Lazy<RSAParameters> rsaParameters;

        static KeyFormatterTests()
        {
            rsaParameters = new Lazy<RSAParameters>(() =>
            {
                var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
                using (var key = algorithm.CreateKeyPair(512))
                {
                    byte[] bcryptNative = key.Export(CryptographicPrivateKeyBlobType.BCryptPrivateKey);
                    var rsaParameters = KeyFormatter.BCryptRsa.Read(bcryptNative);
                    return rsaParameters;
                }
            });
        }

        [Theory, CombinatorialData]
        public void KeyFormatters_PrivateKeyRoundTrip(CryptographicPrivateKeyBlobType format)
        {
            var formatter = KeyFormatter.GetFormatter(format);
            byte[] custom = formatter.Write(rsaParameters.Value);
            var rsaParametersRead = formatter.Read(custom);

            Assert.Equal<byte>(rsaParameters.Value.Exponent, rsaParametersRead.Exponent);
            Assert.Equal<byte>(rsaParameters.Value.Modulus, rsaParametersRead.Modulus);

            Assert.Equal<byte>(rsaParameters.Value.D, rsaParametersRead.D);
            Assert.Equal<byte>(rsaParameters.Value.P, rsaParametersRead.P);
            Assert.Equal<byte>(rsaParameters.Value.Q, rsaParametersRead.Q);
            Assert.Equal<byte>(rsaParameters.Value.DP, rsaParametersRead.DP);
            Assert.Equal<byte>(rsaParameters.Value.DQ, rsaParametersRead.DQ);
            Assert.Equal<byte>(rsaParameters.Value.InverseQ, rsaParametersRead.InverseQ);
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
    }
}
#endif
