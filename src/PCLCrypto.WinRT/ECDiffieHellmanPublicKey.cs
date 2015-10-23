namespace PCLCrypto
{
    using System;
    using Validation;
    using static PInvoke.BCrypt;

    internal class ECDiffieHellmanPublicKey : IECDiffieHellmanPublicKey
    {
        private readonly SafeKeyHandle keyHandle;

        internal ECDiffieHellmanPublicKey(SafeKeyHandle keyHandle)
        {
            Requires.NotNull(keyHandle, nameof(keyHandle));

            this.keyHandle = keyHandle;
        }

        internal SafeKeyHandle Key => this.keyHandle;

        public byte[] ToByteArray()
        {
            return BCryptExportKey(this.keyHandle, null, AsymmetricKeyBlobTypes.EccPublic);
        }
    }
}
