using System;
using System.Text;
using Xamarin.Forms;

using PCLCrypto;
using static PCLCrypto.WinRTCrypto;

namespace PCLCryptoSample
{
    public class App : Application
    {
        private Button createKeyButton = null;
        private Label publicKeyLabel = null;
        private Entry valueText = null;
        private Button encryptButton = null;
        private Label encryptLabel = null;
        private Button decryptButton = null;
        private Label decryptLabel = null;
        private Button hashButton = null;
        private Label hashLabel = null;

        private ICryptographicKey key = null;

        public App()
        {
            // create the key we are going to use
            var asym = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1);
            var hash = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);

            // The root page of your application
            MainPage = new ContentPage
            {
                Content = new StackLayout
                {
                    VerticalOptions = LayoutOptions.Center,
                    Children = {
                        // create a key
                        (createKeyButton = new Button {
                            Text = "Create Key",
                            Command = new Command(() => {
                                key = asym.CreateKeyPair(512);
                                var publicKey = key.ExportPublicKey();
                                var publicKeyString = Convert.ToBase64String(publicKey);
                                
                                publicKeyLabel.Text = publicKeyString;
                            })
                        }),
                        (publicKeyLabel = new Label {
                            Text = "..."
                        }),
                        // enter plain text
                        (valueText = new Entry {
                            Text = "Hello World!"
                        }),
                        // start encryption
                        (encryptButton = new Button {
                            Text = "Encrypt",
                            Command = new Command(() => {
                                try {
                                    var plainString = valueText.Text;
                                    var plain = Encoding.UTF8.GetBytes(plainString);
                                    var encrypted = CryptographicEngine.Encrypt(key, plain);
                                    var encryptedString = Convert.ToBase64String(encrypted);

                                    encryptLabel.Text = encryptedString;
                                } catch (Exception ex) {
                                    encryptLabel.Text = "Error encrypting: " + ex.Message;
                                }
                            })
                        }),
                        (encryptLabel = new Label {
                            Text = "..."
                        }),
                        // and now decrypt
                        (decryptButton = new Button {
                            Text = "Decrypt",
                            Command = new Command(() => {
                                try {
                                    var encryptedString = encryptLabel.Text;
                                    var encrypted = Convert.FromBase64String(encryptedString);
                                    var decrypted = CryptographicEngine.Decrypt(key, encrypted);
                                    var decryptedString = Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);

                                    decryptLabel.Text = decryptedString;
                                } catch (Exception ex) {
                                    decryptLabel.Text = "Error decrypting: " + ex.Message;
                                }
                            })
                        }),
                        (decryptLabel = new Label {
                            Text = "..."
                        }),
                        // and hash
                        (hashButton = new Button {
                            Text = "hash",
                            Command = new Command(() => {
                                try {
                                    var plainString = valueText.Text;
                                    var plain = Encoding.UTF8.GetBytes(plainString);
                                    var hashed = hash.HashData(plain);
                                    var hashedString = Convert.ToBase64String(hashed);

                                    hashLabel.Text = hashedString;
                                } catch (Exception ex) {
                                    hashLabel.Text = "Error hashing: " + ex.Message;
                                }
                            })
                        }),
                        (hashLabel = new Label {
                            Text = "..."
                        })
                    }
                }
            };

            // set initial data
            createKeyButton.Command.Execute(null);
            encryptButton.Command.Execute(null);
            decryptButton.Command.Execute(null);
            hashButton.Command.Execute(null);
        }
    }
}
