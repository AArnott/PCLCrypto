//-----------------------------------------------------------------------
// <copyright file="PvkConvert.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Android.App;
    using Android.Content;
    using Android.OS;
    using Android.Runtime;
    using Android.Views;
    using Android.Widget;
    using Java.IO;
    using Java.Lang;
    using Java.Math;
    using Java.Security;
    using Java.Security.Interfaces;
    using Java.Security.Spec;

    internal static class PvkConvert
    {
        private static readonly byte PUBLICKEYBLOB = 0x06;
        private static readonly byte PRIVATEKEYBLOB = 0x07;
        private static readonly byte CUR_BLOB_VERSION = 0x02;
        private static readonly short RESERVED = 0x0000;
        private static readonly int CALG_RSA_KEYX = 0x0000a400;
        private static readonly int CALG_RSA_SIGN = 0x00002400;
        internal static readonly int AT_KEYEXCHANGE = 1;
        internal static readonly int AT_SIGNATURE = 2;
        private static readonly int[] KEYSPECS = { 0, CALG_RSA_KEYX, CALG_RSA_SIGN };
        private static readonly string MAGIC1 = "RSA1"; 	// 0x31415352
        private static readonly string MAGIC2 = "RSA2"; 	// 0x32415352

        internal static byte[] privatekeyinfoToPrivatekeyblob(IPrivateKey privateKey, int keyspec)
        {
            if (privateKey == null || (keyspec != AT_KEYEXCHANGE && keyspec != AT_SIGNATURE))
                return null;

            var bos = new MemoryStream();
            DataOutputStream dos = new DataOutputStream(bos);

            IRSAPrivateCrtKey pvkKey = privateKey.JavaCast<IRSAPrivateCrtKey>();

            BigInteger mod = pvkKey.Modulus;
            byte[] modulus = mod.ToByteArray();

            int bytelen, bitlen;
            if (modulus[0] == 0)     //if high-order byte is zero, it's for sign bit; don't count in bit-size calculation
                bytelen = modulus.Length - 1;
            else
                bytelen = modulus.Length;
            bitlen = 8 * bytelen;


            dos.Write(PRIVATEKEYBLOB);
            dos.Write(CUR_BLOB_VERSION);
            dos.WriteShort(RESERVED);
            writeLEInt(KEYSPECS[keyspec], dos);    //write Little Endian
            dos.WriteBytes(MAGIC2);
            writeLEInt(bitlen, dos);		//write Little Endian
            int pubexp = Integer.ParseInt(pvkKey.PublicExponent.ToString());
            writeLEInt(pubexp, dos);		//write Little Endian

            byte[] data = modulus;
            ReverseMemory(data);	//reverse array to Little Endian order; since data is same ref. as modulus, modulus is also reversed.
            dos.Write(data, 0, bytelen);	// note that modulus may contain an extra zero byte (highest order byte after reversing)
            // specifying bytelen bytes to write will drop high-order zero byte

            data = pvkKey.PrimeP.ToByteArray();
            ReverseMemory(data);
            dos.Write(data, 0, bytelen / 2);

            data = pvkKey.PrimeQ.ToByteArray();
            ReverseMemory(data);
            dos.Write(data, 0, bytelen / 2);

            data = pvkKey.PrimeExponentP.ToByteArray();
            ReverseMemory(data);
            dos.Write(data, 0, bytelen / 2);

            data = pvkKey.PrimeExponentQ.ToByteArray();
            ReverseMemory(data);
            dos.Write(data, 0, bytelen / 2);

            data = pvkKey.CrtCoefficient.ToByteArray();
            ReverseMemory(data);
            dos.Write(data, 0, bytelen / 2);

            data = pvkKey.PrivateExponent.ToByteArray();
            ReverseMemory(data);
            dos.Write(data, 0, bytelen);
            dos.Flush();
            dos.Close();
            return bos.ToArray();
        }

        private static void writeLEInt(int i, OutputStream output)
        {
            output.Write(i & 0xFF);
            output.Write((i >> 8) & 0xFF);
            output.Write((i >> 16) & 0xFF);
            output.Write((i >> 24) & 0xFF);
        }

        private static void ReverseMemory(byte[] pBuffer)
        {
            byte b;
            int iLength = pBuffer.Length;
            for (int i = 0; i < iLength / 2; i++)
            {
                b = pBuffer[i];
                pBuffer[i] = pBuffer[iLength - i - 1];
                pBuffer[iLength - i - 1] = b;
            }
        }
    }
}