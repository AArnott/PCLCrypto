namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Numerics;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Xunit;

    public class RSAPrivateKeyCompletionTests
    {
        [Fact]
        public void Experiments()
        {
            var rsa = new RSACryptoServiceProvider(512);
            var parameters = rsa.ExportParameters(true);

            var p = new BigInteger(parameters.P);
            var q = new BigInteger(parameters.Q);
            var n = p * q;
            Assert.Equal(parameters.Modulus, n.ToByteArray());

            ////var reconstructed = CreateRSAPrivateKey(parameters.Modulus, parameters.D, parameters.Exponent);

        }

        /// EXAMPLE (Hex Strings)
        /// N(MODULUS) = "DB2CB41E112BACFA2BD7C3D3D7967E84FB9434FC261F9D090A8983947DAF8488D3DF8FBDCC1F92493585E134A1B42DE519F463244D7ED384E26D516CC7A4FF7895B1992140043AACADFC12E856B202346AF8226B1A882137DC3C5A57F0D2815C1FCD4BB46FA9157FDFFD79EC3A10A824CCC1EB3CE0B6B4396AE236590016BA69"
        /// D(PRIVATE EXPONENT) = "18B44A3D155C61EBF4E3261C8BB157E36F63FE30E9AF28892B59E2ADEB18CC8C8BAD284B9165819CA4DEC94AA06B69BCE81706D1C1B668EB128695E5F7FEDE18A908A3011A646A481D3EA71D8A387D474609BD57A882B182E047DE80E04B4221416BD39DFA1FAC0300641962ADB109E28CAF50061B68C9CABD9B00313C0F46ED"
        /// E(PUBLIC EXPONENT) = "010001"
        /// RESULTS: 
        /// DP = "899324E9A8B70CA05612D8BAE70844BBF239D43E2E9CCADFA11EBD43D0603FE70A63963FE3FFA38550B5FEB3DA870D2677927B91542D148FA4BEA6DCD6B2FF57"
        /// DQ = "E43C98265BF97066FC078FD464BFAC089628765A0CE18904F8C15318A6850174F1A4596D3E8663440115D0EEB9157481E40DCA5EE569B1F7F4EE30AC0439C637"
        /// INVERSEQ = "395B8CF3240C325B0F5F86A05ABCF0006695FAB9235589A56759ECBF2CD3D3DFDE0D6F16F0BE5C70CEF22348D2D09FA093C01D909D25BC1DB11DF8A4F0CE552"
        /// P = "ED6CF6699EAC99667E0AFAEF8416F902C00B42D6FFA2C3C18C7BE4CF36013A91F6CF23047529047660DE14A77D13B74FF31DF900541ED37A8EF89340C623759B"
        /// Q = "EC52382046AA660794CC1A907F8031FDE1A554CDE17E8AA216AEDC92DB2E58B0529C76BD0498E00BAA792058B2766C40FD7A9CC2F6782942D91471905561324B"

        ////public static RSAParameters CreateRSAPrivateKey(byte[] mod, byte[] privExponent, byte[] pubExponent)
        ////{
        ////    var n = new BigInteger(mod);
        ////    var d = new BigInteger(privExponent);
        ////    var e = new BigInteger(pubExponent);

        ////    var zero = new BigInteger(0);
        ////    var one = new BigInteger(1);
        ////    var two = new BigInteger(2);
        ////    var four = new BigInteger(4);

        ////    BigInteger de = e * d;
        ////    BigInteger modulusplus1 = n + one;
        ////    BigInteger deminus1 = de - one;
        ////    BigInteger p = zero;
        ////    BigInteger q = zero;

        ////    BigInteger kprima = de / n;

        ////    var ks = new[] { kprima, kprima - one, kprima + one };

        ////    bool bfound = false;
        ////    foreach (BigInteger k in ks)
        ////    {
        ////        BigInteger fi = deminus1 / k;
        ////        BigInteger pplusq = modulusplus1 - fi;
        ////        BigInteger delta = pplusq * pplusq - n * four;

        ////        BigInteger sqrt = delta.sqrt();
        ////        p = (pplusq + sqrt) / two;
        ////        if (n % p != zero) continue;
        ////        q = (pplusq - sqrt) / two;
        ////        bfound = true;
        ////        break;
        ////    }

        ////    if (bfound)
        ////    {
        ////        BigInteger dp = d % (p - one);
        ////        BigInteger dq = d % (q - one);

        ////        BigInteger inverseq = q.modInverse(p);

        ////        var pars = new RSAParameters
        ////        {
        ////            D = d.ToByteArray(),
        ////            DP = dp.ToByteArray(),
        ////            DQ = dq.ToByteArray(),
        ////            Exponent = e.ToByteArray(),
        ////            Modulus = n.ToByteArray(),
        ////            P = p.ToByteArray(),
        ////            Q = q.ToByteArray(),
        ////            InverseQ = inverseq.ToByteArray()
        ////        };
        ////        return pars;
        ////    }

        ////    throw new CryptographicException("Error generating the private key");
        ////}
    }
}
