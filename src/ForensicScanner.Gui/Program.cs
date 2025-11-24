using ForensicScanner.Core.Admin;

namespace ForensicScanner.Gui;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        if (!AdminChecker.IsRunningAsAdministrator())
        {
            MessageBox.Show(
                AdminChecker.GetAdminErrorMessage(),
                "Administrator Required",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
