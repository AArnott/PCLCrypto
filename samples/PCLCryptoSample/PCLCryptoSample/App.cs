// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCryptoSample
{
    using System;
    using System.Text;
    using PCLCrypto;
    using Xamarin.Forms;
    using static PCLCrypto.WinRTCrypto;

    public class App : Application
    {
        private Button? createKeyButton = null;
        private Label? publicKeyLabel = null;
        private Entry? valueText = null;
        private Button? encryptButton = null;
        private Label? encryptLabel = null;
        private Button? decryptButton = null;
        private Label? decryptLabel = null;
        private Button? hashButton = null;
        private Label? hashLabel = null;

        private ICryptographicKey key = null;

        public App()
        {
            // create the key we are going to use
            IAsymmetricKeyAlgorithmProvider? asym = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1);
            IHashAlgorithmProvider? hash = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);

            // The root page of your application
            this.MainPage = new ContentPage
            {
                Content = new StackLayout
                {
                    VerticalOptions = LayoutOptions.Center,
                    Children =
                    {
                        // create a key
                        (this.createKeyButton = new Button
                        {
                            Text = "Create Key",
                            Command = new Command(() =>
                            {
                                this.key = asym.CreateKeyPair(512);
                                var publicKey = this.key.ExportPublicKey();
                                var publicKeyString = Convert.ToBase64String(publicKey);

                                this.publicKeyLabel.Text = publicKeyString;
                            }),
                        }),
                        (this.publicKeyLabel = new Label
                        {
                            Text = "...",
                        }),

                        // enter plain text
                        (this.valueText = new Entry
                        {
                            Text = "Hello World!",
                        }),

                        // start encryption
                        (this.encryptButton = new Button
                        {
                            Text = "Encrypt",
                            Command = new Command(() =>
                            {
                                try
                                {
                                    var plainString = this.valueText.Text;
                                    var plain = Encoding.UTF8.GetBytes(plainString);
                                    var encrypted = CryptographicEngine.Encrypt(this.key, plain);
                                    var encryptedString = Convert.ToBase64String(encrypted);

                                    this.encryptLabel.Text = encryptedString;
                                }
                                catch (Exception ex)
                                {
                                    this.encryptLabel.Text = "Error encrypting: " + ex.Message;
                                }
                            }),
                        }),
                        (this.encryptLabel = new Label
                        {
                            Text = "..."
                        }),

                        // and now decrypt
                        (this.decryptButton = new Button
                        {
                            Text = "Decrypt",
                            Command = new Command(() =>
                            {
                                try
                                {
                                    var encryptedString = this.encryptLabel.Text;
                                    var encrypted = Convert.FromBase64String(encryptedString);
                                    var decrypted = CryptographicEngine.Decrypt(this.key, encrypted);
                                    var decryptedString = Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);

                                    this.decryptLabel.Text = decryptedString;
                                }
                                catch (Exception ex)
                                {
                                    this.decryptLabel.Text = "Error decrypting: " + ex.Message;
                                }
                            }),
                        }),
                        (this.decryptLabel = new Label
                        {
                            Text = "...",
                        }),
                        // and hash
                        (this.hashButton = new Button
                        {
                            Text = "hash",
                            Command = new Command(() =>
                            {
                                try
                                {
                                    var plainString = this.valueText.Text;
                                    var plain = Encoding.UTF8.GetBytes(plainString);
                                    var hashed = hash.HashData(plain);
                                    var hashedString = Convert.ToBase64String(hashed);

                                    this.hashLabel.Text = hashedString;
                                }
                                catch (Exception ex)
                                {
                                    this.hashLabel.Text = "Error hashing: " + ex.Message;
                                }
                            }),
                        }),
                        (this.hashLabel = new Label
                        {
                            Text = "...",
                        }),
                    },
                },
            };

            // set initial data
            this.createKeyButton.Command.Execute(null);
            this.encryptButton.Command.Execute(null);
            this.decryptButton.Command.Execute(null);
            this.hashButton.Command.Execute(null);
        }
    }
}
