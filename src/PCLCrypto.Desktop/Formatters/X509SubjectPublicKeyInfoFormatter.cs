//-----------------------------------------------------------------------
// <copyright file="X509SubjectPublicKeyInfoFormatter.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
//     Portions of this inspired by Patrick Hogan:
//         https://github.com/kuapay/iOS-Certificate--Key--and-Trust-Sample-Project/blob/master/Crypto/Crypto/Crypto/BDRSACryptor.m
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
    /// Encodes/decodes public keys in the X.509 subject public key info format.
    /// </summary>
    internal static class X509SubjectPublicKeyInfoFormatter
    {
        /// <summary>
        /// The OID sequence to include at the start of an X.509 public key certificate.
        /// </summary>
        private static readonly byte[] OidSequence = new byte[] { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

        /// <summary>
        /// Reads the public key information from an X509 subject public key info blob.
        /// </summary>
        /// <param name="keyBlob">The key blob.</param>
        /// <returns>The <see cref="RSAParameters"/> describing the public key.</returns>
        internal static RSAParameters ReadX509SubjectPublicKeyInfo(byte[] keyBlob)
        {
            byte[] rsaPublicKey = GetRawPublicKeyDataFromX509(keyBlob);
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

            var rsaPublicKeyStream = new MemoryStream();
            rsaPublicKeyStream.WritePkcs1(value, includePrivateKey: false);
            byte[] rsaPublicKey = rsaPublicKeyStream.ToArray();

            byte[] builder = new byte[15];
            int bitstringEncLength;
            if (rsaPublicKey.Length + 1 < 128)
            {
                bitstringEncLength = 1;
            }
            else
            {
                bitstringEncLength = ((rsaPublicKey.Length + 1) / 256) + 2;
            }

            builder[0] = 0x30;
            int i = OidSequence.Length + 2 + bitstringEncLength + rsaPublicKey.Length;
            int j = Encode(builder, 1, i);

            stream.Write(builder, 0, j + 1);
            stream.Write(OidSequence, 0, OidSequence.Length);
            builder[0] = 0x03;
            j = Encode(builder, 1, rsaPublicKey.Length + 1);
            builder[j + 1] = 0x00;
            stream.Write(builder, 0, j + 2);
            stream.Write(rsaPublicKey, 0, rsaPublicKey.Length);
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

        /// <summary>
        /// Gets the PKCS#1 rsaPublicKey data from an X.509 blob.
        /// </summary>
        /// <param name="keyBlob">The X.509 certificate.</param>
        /// <returns>The PKCS#1 rsaPublicKey blob.</returns>
        private static byte[] GetRawPublicKeyDataFromX509(byte[] keyBlob)
        {
            int i = 0;
            if (keyBlob[i++] != 0x30)
            {
                throw new ArgumentException("Bad format.");
            }

            if (keyBlob[i] > 0x80)
            {
                i += keyBlob[i] - 0x80 + 1;
            }
            else
            {
                i++;
            }

            if (i >= keyBlob.Length)
            {
                throw new ArgumentException("Bad format");
            }

            if (keyBlob[i] != 0x30)
            {
                throw new ArgumentException("Bad format");
            }

            i += OidSequence.Length;

            if (i >= keyBlob.Length - 2)
            {
                throw new ArgumentException("Bad format");
            }

            if (keyBlob[i++] != 0x03)
            {
                throw new ArgumentException("Bad format");
            }

            if (keyBlob[i] > 0x80)
            {
                i += keyBlob[i] - 0x80 + 1;
            }
            else
            {
                i++;
            }

            if (i >= keyBlob.Length)
            {
                throw new ArgumentException("Bad format");
            }

            if (keyBlob[i++] != 0x00)
            {
                throw new ArgumentException("Bad format");
            }

            if (i >= keyBlob.Length)
            {
                throw new ArgumentException("Bad format");
            }

            byte[] strippedPublicKeyData = new byte[keyBlob.Length - i];
            Array.Copy(keyBlob, i, strippedPublicKeyData, 0, strippedPublicKeyData.Length);

            return strippedPublicKeyData;
        }

        /// <summary>
        /// No idea what it does. I think it's a part of an ASN.1 encoder.
        /// </summary>
        /// <param name="buffer">A buffer to write to.</param>
        /// <param name="offset">The index at which writing into the buffer starts.</param>
        /// <param name="length">The length to encode into the buffer maybe?</param>
        /// <returns>The number of bytes written into the buffer, I think.</returns>
        private static int Encode(byte[] buffer, int offset, int length)
        {
            if (length < 128)
            {
                buffer[offset] = (byte)length;
                return 1;
            }

            int i = (length / 256) + 1;
            buffer[offset] = (byte)(i + 0x80);
            for (int j = 0; j < i; ++j)
            {
                buffer[offset + i - j] = (byte)(length & 0xff);
                length = length >> 8;
            }

            return i + 1;
        }
    }
}
