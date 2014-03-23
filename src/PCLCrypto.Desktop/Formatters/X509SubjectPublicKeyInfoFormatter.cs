//-----------------------------------------------------------------------
// <copyright file="X509SubjectPublicKeyInfoFormatter.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Validation;

    /// <summary>
    /// Encodes/decodes public keys in the X.509 subject public key info format.
    /// </summary>
    internal static class X509SubjectPublicKeyInfoFormatter
    {
        internal static RSAParameters ReadX509SubjectPublicKeyInfo(byte[] keyBlob)
        {
            return ReadX509SubjectPublicKeyInfo(new MemoryStream(keyBlob));
        }

        /// <summary>
        /// Reads the public key information from an X509 subject public key info blob.
        /// </summary>
        /// <param name="stream">The key blob.</param>
        /// <returns>The <see cref="RSAParameters"/> describing the public key.</returns>
        internal static RSAParameters ReadX509SubjectPublicKeyInfo(Stream stream)
        {
            var sequence = stream.ReadAsn1Elements().First();
            if (sequence.Class != Asn.BerClass.Universal || sequence.PC != Asn.BerPC.Constructed || sequence.Tag != Asn.BerTag.Sequence)
            {
                throw new ArgumentException("Unexpected format.");
            }

            var elements = Asn.ReadAsn1Elements(sequence.Content).ToList();
            if (elements.Count != 2 || elements[0].Class != Asn.BerClass.Universal || elements[0].PC != Asn.BerPC.Constructed || elements[0].Tag != Asn.BerTag.Sequence)
            {
                throw new ArgumentException("Unexpected format.");
            }

            var oid = Asn.ReadAsn1Elements(elements[0].Content).First();
            if (!BufferEqual(Pkcs1KeyFormatter.RsaEncryptionObjectIdentifier, oid.Content))
            {
                throw new ArgumentException("Unexpected algorithm.");
            }

            if (elements[1].Class != Asn.BerClass.Universal || elements[1].PC != Asn.BerPC.Primitive || elements[1].Tag != Asn.BerTag.BitString || elements[1].Content[0] != 0)
            {
                throw new ArgumentException("Unexpected format.");
            }

            byte[] rsaPublicKey = TrimLeadingZero(elements[1].Content);
            return Pkcs1KeyFormatter.ReadPkcs1PublicKey(rsaPublicKey);
        }

        /// <summary>
        /// Writes a public key to a stream formatted as a X509 subject public key info blob.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="value">The key.</param>
        internal static void WriteX509SubjectPublicKeyInfo(this Stream stream, RSAParameters value)
        {
            Requires.NotNull(stream, "stream");

            var rootElement = new Asn.DataElement(
                Asn.BerClass.Universal,
                Asn.BerPC.Constructed,
                Asn.BerTag.Sequence,
                new Asn.DataElement(
                    Asn.BerClass.Universal,
                    Asn.BerPC.Constructed,
                    Asn.BerTag.Sequence,
                    new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.ObjectIdentifier,
                        Pkcs1KeyFormatter.RsaEncryptionObjectIdentifier),
                    new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.Null,
                        new byte[0])),
                new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.BitString,
                        PrependLeadingZero(Pkcs1KeyFormatter.WritePkcs1(PublicKeyFilter(value), includePrivateKey: false, prependLeadingZeroOnCertainElements: true))));
            stream.WriteAsn1Element(rootElement);
        }

        /// <summary>
        /// Writes a public key to a stream formatted as a X509 subject public key info blob.
        /// </summary>
        /// <param name="value">The key.</param>
        /// <returns>The formatted key blob.</returns>
        internal static byte[] WriteX509SubjectPublicKeyInfo(RSAParameters value)
        {
            var stream = new MemoryStream();
            WriteX509SubjectPublicKeyInfo(stream, value);
            return stream.ToArray();
        }

        /// <summary>
        /// Returns an instance of <see cref="RSAParameters"/> that does not contain private key info.
        /// </summary>
        /// <param name="value">The RSA parameters which may include a private key.</param>
        /// <returns>An instance of <see cref="RSAParameters"/> that only includes public key information.</returns>
        internal static RSAParameters PublicKeyFilter(this RSAParameters value)
        {
            return new RSAParameters
            {
                Modulus = value.Modulus,
                Exponent = value.Exponent,
            };
        }

        internal static bool BufferEqual(byte[] buffer1, byte[] buffer2)
        {
            if (buffer1.Length != buffer2.Length)
            {
                return false;
            }

            for (int i = 0; i < buffer1.Length; i++)
            {
                if (buffer1[i] != buffer2[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Returns a buffer with a 0x00 byte prepended.
        /// </summary>
        /// <param name="buffer">The buffer to prepend.</param>
        /// <returns>A buffer with the prepended zero.</returns>
        private static byte[] PrependLeadingZero(byte[] buffer)
        {
            byte[] modifiedBuffer = new byte[buffer.Length + 1];
            Buffer.BlockCopy(buffer, 0, modifiedBuffer, 1, buffer.Length);
            return modifiedBuffer;
        }

        /// <summary>
        /// Trims up to one leading byte from the start of a buffer if that byte is a 0x00
        /// without modifying the original buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <returns>A buffer without a leading zero. It may be the same buffer as was provided if no leading zero was found.</returns>
        internal static byte[] TrimLeadingZero(byte[] buffer)
        {
            if (buffer.Length > 0 && buffer[0] == 0)
            {
                byte[] trimmed = new byte[buffer.Length - 1];
                Buffer.BlockCopy(buffer, 1, trimmed, 0, trimmed.Length);
                return trimmed;
            }

            return buffer;
        }
    }
}
