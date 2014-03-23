namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// Spec found at: http://tools.ietf.org/html/rfc5208#page-3
    /// </remarks>
    internal static class Pkcs8KeyFormatter
    {
        internal static RSAParameters ReadPkcs8PrivateKeyInfo(byte[] privateKeyInfo)
        {
            return ReadPkcs8PrivateKeyInfo(new MemoryStream(privateKeyInfo));
        }

        internal static RSAParameters ReadPkcs8PrivateKeyInfo(this Stream stream)
        {
            var universalConstructedSequence = stream.ReadAsn1Elements().Single();
            var sequence = Asn.ReadAsn1Elements(universalConstructedSequence.Content).ToList();
            if (sequence[0].Content.Length != 1 || sequence[0].Content[0] != 0x00)
            {
                throw new ArgumentException("Unrecognized version.");
            }

            if (!X509SubjectPublicKeyInfoFormatter.BufferEqual(Asn.ReadAsn1Elements(sequence[1].Content).First().Content, Pkcs1KeyFormatter.RsaEncryptionObjectIdentifier))
            {
                throw new ArgumentException("Unrecognized object identifier.");
            }

            return Pkcs1KeyFormatter.ReadPkcs1PrivateKey(sequence[2].Content);
        }

        internal static byte[] WritePkcs8PrivateKeyInfo(RSAParameters parameters)
        {
            var rootElement = new Asn.DataElement(
                Asn.BerClass.Universal,
                Asn.BerPC.Constructed,
                Asn.BerTag.Sequence,
                new Asn.DataElement( // Version 0
                    Asn.BerClass.Universal,
                    Asn.BerPC.Primitive,
                    Asn.BerTag.Integer,
                    new byte[] { 0x00 }),
                new Asn.DataElement(
                    Asn.BerClass.Universal,
                    Asn.BerPC.Constructed,
                    Asn.BerTag.Sequence,
                    new Asn.DataElement( // privateKeyAlgorithm
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.ObjectIdentifier,
                        Pkcs1KeyFormatter.RsaEncryptionObjectIdentifier),
                    new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.Null,
                        new byte[0])),
                new Asn.DataElement( // rsaPrivateKey
                    Asn.BerClass.Universal,
                    Asn.BerPC.Primitive,
                    Asn.BerTag.OctetString,
                    Pkcs1KeyFormatter.WritePkcs1(parameters, includePrivateKey: true, prependLeadingZeroOnCertainElements: true)),
                new Asn.DataElement(
                    Asn.BerClass.ContextSpecific,
                    Asn.BerPC.Constructed,
                    Asn.BerTag.EndOfContent,
                    new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Constructed,
                        Asn.BerTag.Sequence,
                        new Asn.DataElement(
                            Asn.BerClass.Universal,
                            Asn.BerPC.Primitive,
                            Asn.BerTag.ObjectIdentifier,
                            new byte[] { 0x55, 0x1d, 0x0f }),
                        new Asn.DataElement(
                            Asn.BerClass.Universal,
                            Asn.BerPC.Constructed,
                            Asn.BerTag.SetAndSetOf,
                            new Asn.DataElement(
                                Asn.BerClass.Universal,
                                Asn.BerPC.Primitive,
                                Asn.BerTag.BitString,
                                new byte[] { 0x00, 0x10 })))));

            return Asn.WriteAsn1Element(rootElement);
        }
    }
}
