namespace PCLCrypto.Tests.WindowsPhone
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Threading.Tasks;
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
            this.TestRunProgress.Visibility = Visibility.Visible;
            this.TextSummaryText.Visibility = Visibility.Collapsed;

            try
            {
                var testRunner = new TestRunner(typeof(RandomNumberGeneratorTests).Assembly);
                await Task.Run(() => testRunner.RunTestsAsync());
                this.TextSummaryText.Text = string.Format(
                    CultureInfo.CurrentCulture,
                    "{0}/{1} tests passed ({2}%)",
                    testRunner.PassCount,
                    testRunner.TestCount,
                    100 * testRunner.PassCount / testRunner.TestCount);
                this.TextSummaryText.Visibility = Visibility.Visible;
                this.ResultsTextBox.Text = testRunner.Log;
            }
            catch (Exception ex)
            {
                this.ResultsTextBox.Text = ex.ToString();
            }
            finally
            {
                this.RunTestsButton.IsEnabled = true;
                this.TestRunProgress.Visibility = Visibility.Collapsed;
            }
        }
    }
}