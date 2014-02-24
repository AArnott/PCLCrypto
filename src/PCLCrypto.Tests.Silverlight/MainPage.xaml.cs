namespace PCLCrypto.Tests.Silverlight
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
    using PCLTesting.Infrastructure;

    public partial class MainPage : UserControl
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void RunTestsButton_Click(object sender, RoutedEventArgs e)
        {
            RunTestsButton.IsEnabled = false;

            try
            {
                var testRunner = new TestRunner(typeof(RandomNumberGeneratorTests).Assembly);
                await testRunner.RunTestsAsync();
                ResultsTextBox.Text = testRunner.Log;
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text = ex.ToString();
            }

            RunTestsButton.IsEnabled = true;
        }
    }
}
