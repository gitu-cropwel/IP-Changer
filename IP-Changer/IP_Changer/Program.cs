using System;
using System.Windows.Forms;

namespace IP_Changer {
    internal static class Program {
        [STAThread]
        private static void Main() {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new IPChanger());
        }
    }
}

