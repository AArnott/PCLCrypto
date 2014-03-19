//-----------------------------------------------------------------------
// <copyright file="Pkcs1KeyFormatter.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Validation;

    /// <summary>
    /// Encodes/decodes public keys and private keys in the PKCS#1 format
    /// (rsaPublicKey and rsaPrivateKey).
    /// </summary>
    internal static class Pkcs1KeyFormatter
    {
        /// <summary>
        /// Reads a PKCS1 private key from a stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>The <see cref="RSAParameters"/> read from the stream.</returns>
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

        /// <summary>
        /// Reads a PKCS1 public key from a stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>The <see cref="RSAParameters"/> read from the stream.</returns>
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

        /// <summary>
        /// Reads a PKCS1 private key from a buffer.
        /// </summary>
        /// <param name="keyBlob">The buffer.</param>
        /// <returns>The <see cref="RSAParameters"/> read from the buffer.</returns>
        internal static RSAParameters ReadPkcs1PrivateKey(byte[] keyBlob)
        {
            return ReadPkcs1PrivateKey(new MemoryStream(keyBlob));
        }

        /// <summary>
        /// Reads a PKCS1 public key from a buffer.
        /// </summary>
        /// <param name="keyBlob">The buffer.</param>
        /// <returns>The <see cref="RSAParameters"/> read from the buffer.</returns>
        internal static RSAParameters ReadPkcs1PublicKey(byte[] keyBlob)
        {
            return ReadPkcs1PublicKey(new MemoryStream(keyBlob));
        }

        /// <summary>
        /// Writes an RSA key to a stream in the PKCS#1 format.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="value">The RSA key to write to the stream.</param>
        /// <param name="includePrivateKey">if set to <c>true</c> the serialized form will include the private key.</param>
        internal static void WritePkcs1(this Stream stream, RSAParameters value, bool includePrivateKey)
        {
            Requires.NotNull(stream, "stream");
            Requires.Argument(!includePrivateKey || value.D != null, "value", "Private key not available.");

            var sequence = new MemoryStream();

            if (includePrivateKey)
            {
                // Only include the version element if this is a private key.
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, new byte[1]));
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

        /// <summary>
        /// Writes an RSA key to a buffer in the PKCS#1 format.
        /// </summary>
        /// <param name="value">The RSA key to write to the stream.</param>
        /// <param name="includePrivateKey">if set to <c>true</c> the serialized form will include the private key.</param>
        /// <returns>The buffer containing the PKCS#1 key.</returns>
        internal static byte[] WritePkcs1(RSAParameters value, bool includePrivateKey)
        {
            var stream = new MemoryStream();
            WritePkcs1(stream, value, includePrivateKey);
            return stream.ToArray();
        }

        /// <summary>
        /// Gets the PKCS#1 formatted RSA public key from a PKCS#1 formatted private key.
        /// </summary>
        /// <param name="privateKeyBlob">The PKCS#1 formatted private key.</param>
        /// <returns>The PKCS#1 formatted public key.</returns>
        internal static byte[] GetRSAPublicKeyFromPrivateKey(byte[] privateKeyBlob)
        {
            RSAParameters privateKeyParameters = ReadPkcs1PrivateKey(privateKeyBlob);
            return WritePkcs1(privateKeyParameters, includePrivateKey: false);
        }
    }
}
