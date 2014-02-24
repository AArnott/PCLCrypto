namespace PCLCrypto.Tests.WindowsPhone
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Windows;
    using System.Windows.Controls;
    using System.Windows.Documents;
    using System.Windows.Input;
    using System.Windows.Media;
    using System.Windows.Media.Animation;
    using System.Windows.Shapes;
    using Microsoft.Phone.Controls;
    using PCLTesting.Infrastructure;

    public partial class MainPage : PhoneApplicationPage
    {
        // Constructor
        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void RunTestsButton_Click(object sender, RoutedEventArgs e)
        {
            this.RunTestsButton.IsEnabled = false;

            try
            {
                var testRunner = new TestRunner(typeof(RandomNumberGeneratorTests).Assembly);
                await testRunner.RunTestsAsync();
                this.ResultsTextBox.Text = testRunner.Log;
            }
            catch (Exception ex)
            {
                this.ResultsTextBox.Text = ex.ToString();
            }

            this.RunTestsButton.IsEnabled = true;
        }
    }
}