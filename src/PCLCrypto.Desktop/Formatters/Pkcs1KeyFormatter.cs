namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Validation;

    internal static class Pkcs1KeyFormatter
    {
        internal static RSAParameters ReadPkcs1PrivateKey(this Stream stream)
        {
            Requires.NotNull(stream, "stream");

            var keyBlobElement = Asn.ReadAsn1Elements(stream).First();
            Requires.Argument(
                keyBlobElement.Class == Asn.BerClass.Universal &&
                keyBlobElement.PC == Asn.BerPC.Constructed &&
                keyBlobElement.Tag == Asn.BerTag.Sequence,
                "keyBlob",
                "Unexpected format.");

            stream = new MemoryStream(keyBlobElement.Content);
            var sequence = Asn.ReadAsn1Elements(stream).ToList();
            Requires.Argument(sequence[0].Content.Length == 1 && sequence[0].Content[0] == 0, "keyBlob", "Unsupported version.");

            return new RSAParameters
            {
                Modulus = sequence[1].Content,
                Exponent = sequence[2].Content,
                D = sequence[3].Content,
                P = sequence[4].Content,
                Q = sequence[5].Content,
                DP = sequence[6].Content,
                DQ = sequence[7].Content,
                InverseQ = sequence[8].Content,
            };
        }

        internal static RSAParameters ReadPkcs1PublicKey(this Stream stream)
        {
            Requires.NotNull(stream, "stream");

            var keyBlobElement = Asn.ReadAsn1Elements(stream).First();
            Requires.Argument(
                keyBlobElement.Class == Asn.BerClass.Universal &&
                keyBlobElement.PC == Asn.BerPC.Constructed &&
                keyBlobElement.Tag == Asn.BerTag.Sequence,
                "keyBlob",
                "Unexpected format.");

            stream = new MemoryStream(keyBlobElement.Content);
            var sequence = Asn.ReadAsn1Elements(stream).ToList();
            Requires.Argument(sequence.Count == 2, "stream", "Invalid format.");
            return new RSAParameters
            {
                Modulus = sequence[0].Content,
                Exponent = sequence[1].Content,
            };
        }

        internal static RSAParameters ReadPkcs1PrivateKey(byte[] keyBlob)
        {
            return ReadPkcs1PrivateKey(new MemoryStream(keyBlob));
        }

        internal static RSAParameters ReadPkcs1PublicKey(byte[] keyBlob)
        {
            return ReadPkcs1PublicKey(new MemoryStream(keyBlob));
        }

        internal static void WritePkcs1(this Stream stream, RSAParameters value, bool includePrivateKey)
        {
            Requires.NotNull(stream, "stream");
            Requires.Argument(!includePrivateKey || value.D != null, "value", "Private key not available.");

            var sequence = new MemoryStream();

            if (includePrivateKey)
            {
                // Only include the version element if this is a private key.
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, new byte[0]));
            }

            sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.Modulus));
            sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.Exponent));
            if (includePrivateKey)
            {
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.D));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.P));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.Q));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.DP));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.DQ));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.InverseQ));
            }

            stream.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Constructed, Asn.BerTag.Sequence, sequence.ToArray()));
        }

        internal static byte[] WritePkcs1(RSAParameters value, bool includePrivateKey)
        {
            var stream = new MemoryStream();
            WritePkcs1(stream, value, includePrivateKey);
            return stream.ToArray();
        }

        internal static byte[] GetRSAPublicKeyFromPrivateKey(byte[] privateKeyBlob)
        {
            RSAParameters privateKeyParameters = ReadPkcs1PrivateKey(privateKeyBlob);
            RSAParameters publicKeyParameters = privateKeyParameters.PublicKeyFilter();
            return WritePkcs1(publicKeyParameters, includePrivateKey: false);
        }
    }
}
