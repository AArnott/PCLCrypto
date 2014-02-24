namespace PCLCrypto.Tests.WindowsPhone
{
    using PCLCrypto.Tests.WindowsPhone.Resources;

    /// <summary>
    /// Provides access to string resources.
    /// </summary>
    public class LocalizedStrings
    {
        private static AppResources localizedResources = new AppResources();

        public AppResources LocalizedResources
        {
            get { return localizedResources; }
        }
    }
}