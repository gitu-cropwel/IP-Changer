using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using System.Collections.Generic;
using Microsoft.Win32;

namespace IP_Changer {
    public class IPChanger : Form {
        private String RSA = "109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413";
        private Button button1;
        private Button button2;
        private Button button3;
        private CheckBox checkBox1;
        private IContainer components;
        private Label label1;
        private Label label2;
        private TextBox textBox1;
        private TextBox textBox2;
        public IntPtr ProcessHandle;
        public int selectedClient = 0;
        public bool clientChoosed = false;
        public string getClient;
        public string lastServer = "reptera.net";
        private static List<SignatureEntry> _mcSigs;

        public IPChanger() {
            this.InitializeComponent();
            List<SignatureEntry> list = new List<SignatureEntry>();
            SignatureEntry item = new SignatureEntry {
                Bytes = new byte[] { 
                    0x80, 0xbd, 0x70, 0xf4, 0xff, 0xff, 0, 0x75, 0x40, 0x68, 0xd4, 0x77, 0x70, 0, 0x6a, 0, 
                    0x6a, 0, 0xff, 0x15, 12, 0x42, 0x6c, 0, 0x8b, 0x3d, 0xf4, 0x41, 0x6c, 0, 0xff, 0xd7, 
                    0x3d, 0xb7, 0, 0, 0, 0x74, 7, 0xff, 0xd7, 0x83, 0xf8, 5, 0x75, 0x1b
                 },
                Signature = "x?????xx?x????xxxxx?????x?????xxxxxxxx?xxxxxx?",
                Offset = 7
            };
            list.Add(item);
            SignatureEntry entry2 = new SignatureEntry {
                Bytes = new byte[] { 
                    0x8a, 0x45, 0xe7, 0x84, 0xc0, 0x75, 0x52, 0x68, 60, 4, 0x5d, 0, 0x6a, 0, 0x6a, 0, 
                    0xff, 0x15, 0xe4, 0xa2, 0x5b, 0, 0x89, 0x45, 0x98, 0x8b, 0x3d, 0x38, 0xa2, 0x5b, 0, 0xff, 
                    0xd7, 0x3d, 0xb7, 0, 0, 0, 0x74, 11, 0xff, 0xd7, 0x83, 0xf8, 5, 0x74, 4
                 },
                Signature = "x??xxx?x????xxxxx?????x??x?????xxxxxxxx?xxxxxx?",
                Offset = 5
            };
            list.Add(entry2);
            SignatureEntry entry3 = new SignatureEntry {
                Bytes = new byte[] { 
                    0x8a, 0x45, 0xeb, 0x84, 0xc0, 0x75, 0x5f, 0x6a, 0, 0x68, 0x30, 0xdb, 0x44, 0, 0xc7, 5, 
                    240, 0x45, 0x5f, 0, 0, 0, 0, 0, 0xff, 0x15, 0x74, 0xe4, 0x47, 0, 0xa1, 240, 
                    0x45, 0x5f, 0, 0x85, 0xc0, 0x75, 0x2c, 0x6a, 0x30, 0x68, 180, 0xda, 0x48, 0, 0x68, 0x2c, 
                    0xed, 0x48, 0, 0x6a, 0, 0xff, 0x15, 0x84, 0xe4, 0x47, 0
                 },
                Signature = "x??xxx?xxx????x????xxxxxx?????x????xxx?xxx????x????xxx?????",
                Offset = 5
            };
            list.Add(entry3);
            _mcSigs = list;
        }

        private void button2_Click(object sender, EventArgs e) {
            MessageBox.Show("Supported Clients: 10.37, 10.41, 10.50, 10.51, 10.52, 10.53, 10.54, 10.56", "IP Changer - Help");
        }

        public bool GetProcessPath(string name) {
            Process[] processes = Process.GetProcessesByName(name);
            if (processes.Length > 0) {
                return true;
            } else {
                return false;
            }
        }

        [DllImport("kernel32.dll")]
        private static extern uint SuspendThread(IntPtr hThread);
        public static bool TryPatchMC(IntPtr hProcess, IntPtr baseAddress) {
            IntPtr zero = IntPtr.Zero;
            long codeAddr = -1L;
            byte[] textSectionData = GetSectionBytes(hProcess, baseAddress, ".text", ref zero);
            SignatureEntry entry = _mcSigs.FirstOrDefault<SignatureEntry>(sig => (codeAddr = SearchPatternBytes(textSectionData, sig.Bytes, sig.Signature)) != -1L);
            if (entry == null) {
                return false;
            }
            IntPtr lpAddr = new IntPtr((zero.ToInt64() + codeAddr) + entry.Offset);
            WriteByte(hProcess, lpAddr, 0xeb);
            return true;
        }

        private static int SearchPatternBytes(byte[] haystack, byte[] needle, string needlePattern) {
            int index = 0;
            for (int i = 0; index < haystack.Length; i++) {
                if (needle.Length == i) {
                    return (index - i);
                }
                if ((needlePattern[i] != '?') && (haystack[index] != needle[i])) {
                    i = -1;
                }
                index++;
            }
            return -1;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        private static byte[] GetSectionBytes(IntPtr hProcess, IntPtr baseAddress, string section, ref IntPtr sectionAddress) {
            IMAGE_SECTION_HEADER image_section_header = GetSection(hProcess, baseAddress, section);
            if (image_section_header.Name == null) {
                throw new Exception("Could not find section " + section);
            }
            sectionAddress = new IntPtr(baseAddress.ToInt64() + image_section_header.VirtualAddress);
            return ReadBytes(hProcess, sectionAddress, image_section_header.Misc);
        }

        [DllImport("kernel32.dll")]
        public static extern void GetSystemInfo([MarshalAs(UnmanagedType.Struct)] out SYSTEM_INFO lpSystemInfo);
        private static byte[] ReadBytes(IntPtr hProcess, IntPtr lpAddr, uint bytes) {
            byte[] lpBuffer = new byte[bytes];
            ReadProcessMemory(hProcess, lpAddr, lpBuffer, new UIntPtr(bytes), IntPtr.Zero);
            return lpBuffer;
        }

        [DllImport("kernel32", SetLastError = true)]
        public static extern int GetProcessId(IntPtr hProcess);
        private static IMAGE_SECTION_HEADER GetSection(IntPtr hProcess, IntPtr baseAddress, string section) {
            IMAGE_DOS_HEADER image_dos_header = ReadUnmanagedStructure<IMAGE_DOS_HEADER>(hProcess, baseAddress);
            IntPtr lpAddr = new IntPtr(baseAddress.ToInt64() + (image_dos_header.e_lfanew + 4));
            IMAGE_FILE_HEADER image_file_header = ReadUnmanagedStructure<IMAGE_FILE_HEADER>(hProcess, lpAddr);
            lpAddr = new IntPtr(lpAddr.ToInt64() + (Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) + image_file_header.SizeOfOptionalHeader));
            for (int i = 0; i < image_file_header.NumberOfSections; i++) {
                IMAGE_SECTION_HEADER image_section_header = ReadUnmanagedStructure<IMAGE_SECTION_HEADER>(hProcess, lpAddr);
                lpAddr = new IntPtr(lpAddr.ToInt64() + Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
                for (int j = 0; j < 8; j++) {
                    if (section.Length == j) {
                        return image_section_header;
                    }
                    if (section[j] != image_section_header.Name[j]) {
                        break;
                    }
                }
            }
            return new IMAGE_SECTION_HEADER();
        }

        private static T ReadUnmanagedStructure<T>(IntPtr hProcess, IntPtr lpAddr) {
            byte[] lpBuffer = new byte[Marshal.SizeOf(typeof(T))];
            ReadProcessMemory(hProcess, lpAddr, lpBuffer, new UIntPtr((uint)lpBuffer.Length), IntPtr.Zero);
            GCHandle handle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
            T local = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return local;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_SECTION_HEADER {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint Misc;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

        private class SignatureEntry {
            public byte[] Bytes;
            public int Offset;
            public string Signature;
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetWindowText(IntPtr hwnd, string lpString);
        private void startClient() {
            long[] rsaAdress = new long[] { 0x385990L, 0x385970L, 0x37E900L, 0x373810L, 0x372800L, 0x36F7F0L, 0x33A450L, 0x333320L };
            long[] numArray2 = new long[] { 0x48A234L, 0x48A094L, 0x474DF8L, 0x469878L, 0x46885CL, 0x461738L, 0x41C568L, 0x41343CL }; // ADRESSES OF STATIC TIBIA IP
            long[] numArray3 = new long[] { 0x48A238L, 0x48A098L, 0x474DFCL, 0x46987CL, 0x468860L, 0x46173CL, 0x41C56CL, 0x413440L };
            int[] numArray8 = new int[3];
            numArray8[0] = 0x30;
            numArray8[1] = 0x38;
            int[] numArray4 = numArray8;
            int[] numArray9 = new int[3];
            numArray9[0] = 4;
            numArray9[1] = 4;
            int[] numArray5 = numArray9;
            int[] numArray10 = new int[3];
            numArray10[0] = 0x1c;
            numArray10[1] = 0x20;
            int[] numArray6 = numArray10;
            int[] numArray11 = new int[3];
            numArray11[0] = 40;
            numArray11[1] = 0x30;
            int[] numArray7 = numArray11;
            string[] strArray = new string[] { "10.7.0.0", "10.6.3.0", "10.5.6.0", "10.5.4.0", "10.5.3.0", "10.4.1.0", "10.3.7.0" };
            string[] source = new string[] { "10.5.0.0", "10.5.1.0", "10.5.2.0" };
            int length = strArray.Length - 1;
            short index = 0;
            bool toChange = true;
            Process myProcess = new Process();
            try {
                myProcess.StartInfo.UseShellExecute = false;
                string[] split = getClient.Split(new Char[] { '\\' });
                string dir = "";
                for(int i = 0; i<split.Length-1; i++) {
                    dir += split[i]+"\\";
                }
                myProcess.StartInfo.WorkingDirectory = @"" + dir + "";
                myProcess.StartInfo.FileName = getClient;
                myProcess.StartInfo.CreateNoWindow = true;
                myProcess.Start();
            } catch (Exception a) {
                myProcess.Close();
            }

            while (toChange) {
                if (GetProcessPath("Tibia")) {
                    Process[] processesByName = Process.GetProcessesByName("Tibia");
                    IntPtr topWindow = FindClient();
                    if ((int)topWindow > 0 && myProcess.Id > 0) {
                        foreach (Process process in processesByName) {
                            if (myProcess.Id == process.Id) {
                                this.ProcessHandle = WinApi.OpenProcess(0x1f0fff, 0, (uint)process.Id);
                                this.BaseAddress = WinApi.GetBaseAddress(this.ProcessHandle).ToInt64();
                                setServer(this.textBox1.Text);
                                string str = process.MainModule.FileVersionInfo.FileVersion.ToString();
                                if (strArray.Contains<String>(str))
                                {
                                    for (int i = 0; i < length; i++)
                                    {
                                        if (strArray[i] == str)
                                        {
                                            if (i >= 5)
                                                selectedClient = i + 1;
                                            else
                                                selectedClient = i;
                                        }
                                    }
                                }
                                else if (source.Contains<String>(str))
                                {
                                    selectedClient = 5;
                                }
                                else
                                {
                                    MessageBox.Show("This Tibia Client is not supported!", "IP Changer", MessageBoxButtons.OK);
                                    break;
                                }
                                int num2 = int.Parse(str.Replace(".", ""));
                                if ((num2 >= 0x2774) && (num2 < 0x2904))
                                {
                                    index = 1;
                                }
                                else if (num2 == 860)
                                {
                                    index = 2;
                                }
                                Memory.WriteRSA(this.ProcessHandle, this.BaseAddress + rsaAdress[selectedClient], RSA);
                                if (num2 <= 0x3f2)
                                {
                                    long address = this.BaseAddress + numArray2[selectedClient];
                                    for (int i = 0; i < 10; i++)
                                    {
                                        Memory.WriteString(this.ProcessHandle, address, this.textBox1.Text.Trim());
                                        Memory.WriteInt32(this.ProcessHandle, address + 100L, int.Parse(this.textBox2.Text.Trim()));
                                        address += 0x70L;
                                    }
                                    break;
                                }
                                IntPtr ptr = new IntPtr(this.BaseAddress + numArray2[selectedClient]);
                                IntPtr ptr2 = new IntPtr(this.BaseAddress + numArray3[selectedClient]);
                                uint num5 = Memory.ReadUInt32(this.ProcessHandle, (long)ptr);
                                Memory.ReadUInt32(this.ProcessHandle, (long)ptr2);
                                int num1 = numArray4[index];
                                uint num6 = num5;
                                uint num7 = Memory.ReadUInt32(this.ProcessHandle, num6 + numArray6[index]);
                                if (num7 != 0)
                                {
                                    uint num8 = num6 + ((uint)numArray7[index]);
                                    Memory.WriteInt16(this.ProcessHandle, (long)num8, (short)int.Parse(this.textBox2.Text.Trim()));
                                    int num9 = BitConverter.ToInt32(IPAddress.Parse(Dns.GetHostAddresses(this.textBox1.Text.Trim())[0].ToString()).GetAddressBytes(), 0);
                                    Memory.WriteInt32(this.ProcessHandle, (long)num7, num9);
                                    uint num10 = Memory.ReadUInt32(this.ProcessHandle, num6 + numArray5[index]);
                                    Memory.WriteString(this.ProcessHandle, (long)num10, this.textBox1.Text.Trim());
                                }
                                WinApi.SetWindowText(topWindow, "Tibia - " + this.textBox1.Text + ":" + this.textBox2.Text);
                                WinApi.SetForegroundWindow(topWindow);
                                IntPtr baseAddress = WinApi.GetBaseAddress(this.ProcessHandle);
                                TryPatchMC(this.ProcessHandle, baseAddress);
                                WinApi.CloseHandle(this.ProcessHandle);
                            }
                        }
                        break;
                    }
                }
            }
        }

        private void button3_Click(object sender, EventArgs e) {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.FileName = "Tibia";
            dlg.DefaultExt = ".exe";
            dlg.Filter = "Tibia (.exe)|*.exe";
            DialogResult result = dlg.ShowDialog();
            if (result == DialogResult.OK) {
                string file = dlg.FileName;
                getClient = file;
                setPath(file);
            }
        }

        private static void WriteByte(IntPtr hProcess, IntPtr lpAddr, byte v) {
            WriteProcessMemory(hProcess, lpAddr, new byte[] { v }, new IntPtr(1), IntPtr.Zero);
        }

        private static void setPath(string path) {
            const string userRoot = "HKEY_CURRENT_USER\\Software";
            const string subkey = "IP-Changer";
            const string keyName = userRoot + "\\" + subkey;
            Registry.SetValue(keyName, "Path", path);
        }

        private static void setServer(string ip) {
            const string userRoot = "HKEY_CURRENT_USER\\Software";
            const string subkey = "IP-Changer";
            const string keyName = userRoot + "\\" + subkey;
            Registry.SetValue(keyName, "Server", ip);
        }

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesWritten);

        private void button1_Click(object sender, EventArgs e) {
            if (!clientChoosed) {
                OpenFileDialog dlg = new OpenFileDialog();
                dlg.FileName = "Tibia";
                dlg.DefaultExt = ".exe";
                dlg.Filter = "Tibia (.exe)|*.exe";
                DialogResult result = dlg.ShowDialog();
                if (result == DialogResult.OK) {
                    string file = dlg.FileName;
                    getClient = file;
                    setPath(file);
                }
            }
            long[] rsaAdress = new long[] { 0x385990L, 0x385970L, 0x37E900L, 0x373810L, 0x372800L, 0x36F7F0L, 0x33A450L, 0x333320L };
            long[] numArray2 = new long[] { 0x48A234L, 0x48A094L, 0x474DF8L, 0x469878L, 0x46885CL, 0x461738L, 0x41C568L, 0x41343CL }; // ADRESSES OF STATIC TIBIA IP
            long[] numArray3 = new long[] { 0x48A238L, 0x48A098L, 0x474DFCL, 0x46987CL, 0x468860L, 0x46173CL, 0x41C56CL, 0x413440L };
            int[] numArray8 = new int[3];
            numArray8[0] = 0x30;
            numArray8[1] = 0x38;
            int[] numArray4 = numArray8;
            int[] numArray9 = new int[3];
            numArray9[0] = 4;
            numArray9[1] = 4;
            int[] numArray5 = numArray9;
            int[] numArray10 = new int[3];
            numArray10[0] = 0x1c;
            numArray10[1] = 0x20;
            int[] numArray6 = numArray10;
            int[] numArray11 = new int[3];
            numArray11[0] = 40;
            numArray11[1] = 0x30;
            int[] numArray7 = numArray11;
            string[] strArray = new string[] { "10.7.0.0", "10.6.3.0", "10.5.6.0", "10.5.4.0", "10.5.3.0", "10.4.1.0", "10.3.7.0" };
            string[] source = new string[] { "10.5.0.0", "10.5.1.0", "10.5.2.0" };
            int length = strArray.Length - 1;
            short index = 0;
            if (checkBox1.Checked) {
                startClient();
            }
            if (this.textBox1.Text.Length < 1) {
                MessageBox.Show("Please enter an IP address.", "IP Changer", MessageBoxButtons.OK);
            } else {
                IntPtr topWindow = FindClient();
                Process[] processesByName = Process.GetProcessesByName("Tibia");
                if (processesByName.Length < 1) {
                    startClient();
                }
                foreach (Process process in processesByName) {
                    this.ProcessHandle = WinApi.OpenProcess(0x1f0fff, 0, (uint)process.Id);
                    this.BaseAddress = WinApi.GetBaseAddress(this.ProcessHandle).ToInt64();
                    setServer(this.textBox1.Text);
                    string str = process.MainModule.FileVersionInfo.FileVersion.ToString();
                    if (strArray.Contains<String>(str)) {
                        for (int i = 0; i < length; i++) {
                            if (strArray[i] == str) {
                                if (i >= 5)
                                    selectedClient = i + 1;
                                else
                                    selectedClient = i;
                            }
                        }
                    } else if (source.Contains<String>(str)) {
                        selectedClient = 5;
                    } else {
                        MessageBox.Show("This Tibia Client is not supported!", "IP Changer", MessageBoxButtons.OK);
                        break;
                    }

                    //MessageBox.Show("Tibia Client: " + str + " Base: " + this.BaseAddress + "", "Error", MessageBoxButtons.OK);

                    int num2 = int.Parse(str.Replace(".", ""));
                    if ((num2 >= 0x2774) && (num2 < 0x2904)) {
                        index = 1;
                    } else if (num2 == 860) {
                        index = 2;
                    }

                    WinApi.SetWindowText(topWindow, "Tibia - " + this.textBox1.Text + ":" + this.textBox2.Text);
                    WinApi.SetForegroundWindow(topWindow);

                    Memory.WriteRSA(this.ProcessHandle, this.BaseAddress + rsaAdress[selectedClient], RSA);

                    if (num2 <= 0x3f2) {
                        long address = this.BaseAddress + numArray2[selectedClient];
                        for (int i = 0; i < 10; i++) {
                            Memory.WriteString(this.ProcessHandle, address, this.textBox1.Text.Trim());
                            Memory.WriteInt32(this.ProcessHandle, address + 100L, int.Parse(this.textBox2.Text.Trim()));
                            address += 0x70L;
                        }
                        break;
                    }

                    IntPtr ptr = new IntPtr(this.BaseAddress + numArray2[selectedClient]);
                    IntPtr ptr2 = new IntPtr(this.BaseAddress + numArray3[selectedClient]);
                    uint num5 = Memory.ReadUInt32(this.ProcessHandle, (long)ptr);
                    Memory.ReadUInt32(this.ProcessHandle, (long)ptr2);
                    int num1 = numArray4[index];
                    uint num6 = num5;
                    uint num7 = Memory.ReadUInt32(this.ProcessHandle, num6 + numArray6[index]);
                    if (num7 != 0) {
                        uint num8 = num6 + ((uint)numArray7[index]);
                        Memory.WriteInt16(this.ProcessHandle, (long)num8, (short)int.Parse(this.textBox2.Text.Trim()));
                        int num9 = BitConverter.ToInt32(IPAddress.Parse(Dns.GetHostAddresses(this.textBox1.Text.Trim())[0].ToString()).GetAddressBytes(), 0);
                        Memory.WriteInt32(this.ProcessHandle, (long)num7, num9);
                        uint num10 = Memory.ReadUInt32(this.ProcessHandle, num6 + numArray5[index]);
                        Memory.WriteString(this.ProcessHandle, (long)num10, this.textBox1.Text.Trim());
                    }
                    WinApi.CloseHandle(this.ProcessHandle);
                }
            }
        }

        public static IntPtr FindClient() {
            IntPtr ptr = FindWindow("tibiaclient", null);
            if (ptr == IntPtr.Zero) {
                ptr = FindWindow("tibiatestclient", null);
            }
            return ptr;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        protected override void Dispose(bool disposing) {
            if (disposing && (this.components != null)) {
                this.components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent() {
            const string userRoot = "HKEY_CURRENT_USER\\Software";
            const string subkey = "IP-Changer";
            const string keyName = userRoot + "\\" + subkey;
            getClient = (string)Registry.GetValue(keyName,"Path","false");
            if (!getClient.Equals("false")) {
                clientChoosed = true;
            }
            string getServer = (string)Registry.GetValue(keyName, "Server", "false");
            if (!getServer.Equals("false")) {
                lastServer = getServer;
            }
            ComponentResourceManager manager = new ComponentResourceManager(typeof(IPChanger));
            this.button1 = new Button();
            this.button2 = new Button();
            this.button3 = new Button();
            this.textBox1 = new TextBox();
            this.label1 = new Label();
            this.textBox2 = new TextBox();
            this.label2 = new Label();
            this.checkBox1 = new CheckBox();
            base.SuspendLayout();

            this.button2.Location = new Point(189, 28);
            this.button2.Name = "button1";
            this.button2.Size = new Size(0x35, 0x17);
            this.button2.TabIndex = 3;
            this.button2.Text = "Help";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new EventHandler(this.button2_Click);

            this.button1.Location = new Point(5, 28);
            this.button1.Name = "button1";
            this.button1.Size = new Size(180, 23);
            this.button1.TabIndex = 3;
            this.button1.Text = "Apply";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new EventHandler(this.button1_Click);

            this.button3.Location = new Point(142, 51);
            this.button3.Name = "button1";
            this.button3.Size = new Size(100, 23);
            this.button3.TabIndex = 3;
            this.button3.Text = "Client Patch";
            this.button3.UseVisualStyleBackColor = true;
            this.button3.Click += new EventHandler(this.button3_Click);

            this.label1.AutoSize = true;
            this.label1.Location = new Point(4, 9);
            this.label1.Name = "label1";
            this.label1.Size = new Size(20, 13);
            this.label1.TabIndex = 2;
            this.label1.Text = "IP:";

            this.textBox1.Location = new Point(0x19, 6);
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new Size(0x98, 20);
            this.textBox1.TabIndex = 0;
            this.textBox1.Text = lastServer;

            this.label2.AutoSize = true;
            this.label2.Location = new Point(177, 9);
            this.label2.Name = "label1";
            this.label2.Size = new Size(20, 13);
            this.label2.TabIndex = 2;
            this.label2.Text = "Port:";

            this.textBox2.Location = new Point(205, 6);
            this.textBox2.MaxLength = 4;
            this.textBox2.Name = "textBox2";
            this.textBox2.Size = new Size(0x24, 20);
            this.textBox2.TabIndex = 1;
            this.textBox2.Text = "7171";

            this.checkBox1.AutoSize = true;
            this.checkBox1.Enabled = true;
            this.checkBox1.Location = new Point(4, 55);
            this.checkBox1.Name = "checkBox1";
            this.checkBox1.Size = new Size(0x4a, 0x11);
            this.checkBox1.TabIndex = 10;
            this.checkBox1.Text = "MultiClient";
            this.checkBox1.UseVisualStyleBackColor = true;

            base.CenterToParent();
            base.AutoScaleDimensions = new SizeF(6f, 13f);
            base.AutoScaleMode = AutoScaleMode.Font;
            base.ClientSize = new Size(245, 75);
            base.Controls.Add(this.checkBox1);
            base.Controls.Add(this.textBox2);
            base.Controls.Add(this.label1);
            base.Controls.Add(this.label2);
            base.Controls.Add(this.textBox1);
            base.Controls.Add(this.button1);
            base.Controls.Add(this.button2);
            base.Controls.Add(this.button3);
            base.FormBorderStyle = FormBorderStyle.FixedDialog;
            base.MaximizeBox = false;
            base.ShowIcon = true;
            base.Name = "IPChanger";
            this.Text = "IP Changer";
            base.ResumeLayout(false);
            base.PerformLayout();
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e) {
            Process.Start("https://github.com/gitu-cropwel/IP-Changer");
        }

        public long BaseAddress { get; private set; }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential, Pack=1)]
        public struct IMAGE_FILE_HEADER {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        public static class Memory {
            public static byte ReadByte(IntPtr handle, long address) {
                return ReadBytes(handle, address, 1)[0];
            }

            public static byte[] ReadBytes(IntPtr handle, long address, uint bytesToRead) {
                IntPtr ptr;
                byte[] buffer = new byte[bytesToRead];
                IPChanger.WinApi.ReadProcessMemory(handle, new IntPtr(address), buffer, bytesToRead, out ptr);
                return buffer;
            }

            public static double ReadDouble(IntPtr handle, long address) {
                return BitConverter.ToDouble(ReadBytes(handle, address, 8), 0);
            }

            [Obsolete("Please use ReadInt32.")]
            public static int ReadInt(IntPtr handle, long address) {
                return BitConverter.ToInt32(ReadBytes(handle, address, 4), 0);
            }

            public static short ReadInt16(IntPtr handle, long address) {
                return BitConverter.ToInt16(ReadBytes(handle, address, 2), 0);
            }

            public static int ReadInt32(IntPtr handle, long address) {
                return BitConverter.ToInt32(ReadBytes(handle, address, 4), 0);
            }

            [Obsolete("Please use ReadInt16")]
            public static short ReadShort(IntPtr handle, long address) {
                return BitConverter.ToInt16(ReadBytes(handle, address, 2), 0);
            }

            public static string ReadString(IntPtr handle, long address) {
                return ReadString(handle, address, 0);
            }

            public static string ReadString(IntPtr handle, long address, uint length) {
                if (length > 0) {
                    byte[] bytes = ReadBytes(handle, address, length);
                    return Encoding.Default.GetString(bytes).Split(new char[1])[0];
                }
                string str = "";
                address += 1L;
                for (byte i = ReadByte(handle, address); i != 0; i = ReadByte(handle, address)) {
                    str = str + ((char) i);
                    address += 1L;
                }
                return str;
            }

            public static ushort ReadUInt16(IntPtr handle, long address) {
                return BitConverter.ToUInt16(ReadBytes(handle, address, 2), 0);
            }

            public static uint ReadUInt32(IntPtr handle, long address) {
                return BitConverter.ToUInt32(ReadBytes(handle, address, 4), 0);
            }

            public static ulong ReadUInt64(IntPtr handle, long address) {
                return BitConverter.ToUInt64(ReadBytes(handle, address, 8), 0);
            }

            public static bool WriteByte(IntPtr handle, long address, byte value) {
                return WriteBytes(handle, address, new byte[] { value }, 1);
            }

            public static bool WriteBytes(IntPtr handle, long address, byte[] bytes, uint length) {
                IntPtr ptr;
                return (IPChanger.WinApi.WriteProcessMemory(handle, new IntPtr(address), bytes, length, out ptr) != 0);
            }

            public static bool WriteDouble(IntPtr handle, long address, double value) {
                byte[] bytes = BitConverter.GetBytes(value);
                return WriteBytes(handle, address, bytes, 8);
            }

            [Obsolete("Please use WriteInt32.")]
            public static bool WriteInt(IntPtr handle, long address, int value) {
                byte[] bytes = BitConverter.GetBytes(value);
                return WriteBytes(handle, address, bytes, 4);
            }

            public static bool WriteInt16(IntPtr handle, long address, short value) {
                return WriteBytes(handle, address, BitConverter.GetBytes(value), 2);
            }

            public static bool WriteInt32(IntPtr handle, long address, int value) {
                return WriteBytes(handle, address, BitConverter.GetBytes(value), 4);
            }

            public static bool WriteRSA(IntPtr handle, long address, string newKey) {
                IntPtr ptr;
                IPChanger.WinApi.MemoryProtection lpflOldProtect = 0;
                byte[] bytes = new ASCIIEncoding().GetBytes(newKey);
                IPChanger.WinApi.VirtualProtectEx(handle, new IntPtr(address), new IntPtr(bytes.Length), IPChanger.WinApi.MemoryProtection.ExecuteReadWrite, ref lpflOldProtect);
                int num = IPChanger.WinApi.WriteProcessMemory(handle, new IntPtr(address), bytes, (uint)bytes.Length, out ptr);
                IPChanger.WinApi.VirtualProtectEx(handle, new IntPtr(address), new IntPtr(bytes.Length), lpflOldProtect, ref lpflOldProtect);
                return (num != 0);
            }

            public static bool WriteString(IntPtr handle, long address, string str) {
                str = str + '\0';
                byte[] bytes = Encoding.Default.GetBytes(str);
                return WriteBytes(handle, address, bytes, (uint) bytes.Length);
            }

            public static bool WriteStringNoEncoding(IntPtr handle, long address, string str) {
                str = str + '\0';
                byte[] bytes = Encoding.UTF8.GetBytes(str);
                return WriteBytes(handle, address, bytes, (uint) bytes.Length);
            }

            public static bool WriteUInt16(IntPtr handle, long address, ushort value) {
                return WriteBytes(handle, address, BitConverter.GetBytes(value), 2);
            }

            public static bool WriteUInt32(IntPtr handle, long address, uint value) {
                return WriteBytes(handle, address, BitConverter.GetBytes(value), 4);
            }

            public static bool WriteUInt64(IntPtr handle, long address, ulong value) {
                return WriteBytes(handle, address, BitConverter.GetBytes(value), 8);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO {
            public ushort processorArchitecture;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort dwProcessorLevel;
            public ushort dwProcessorRevision;
        }

        public static class WinApi {
            public const uint CREATE_SUSPENDED = 4;
            public const uint HWND_NOTOPMOST = 0xfffffffe;
            public const uint HWND_TOPMOST = uint.MaxValue;
            public const uint MEM_COMMIT = 0x1000;
            public const uint MEM_RELEASE = 0x8000;
            public const uint MEM_RESERVE = 0x2000;
            public const uint PROCESS_ALL_ACCESS = 0x1f0fff;
            public const uint PROCESS_VM_OPERATION = 8;
            public const uint PROCESS_VM_READ = 0x10;
            public const uint PROCESS_VM_WRITE = 0x20;
            public const int SW_HIDE = 0;
            public const int SW_MINIMIZE = 6;
            public const int SW_RESTORE = 9;
            public const int SW_SHOW = 5;
            public const int SW_SHOWDEFAULT = 10;
            public const int SW_SHOWMAXIMIZED = 3;
            public const int SW_SHOWMINIMIZED = 2;
            public const int SW_SHOWMINNOACTIVE = 7;
            public const int SW_SHOWNA = 8;
            public const int SW_SHOWNOACTIVATE = 4;
            public const int SW_SHOWNORMAL = 1;
            public const uint SWP_NOMOVE = 2;
            public const uint SWP_NOSIZE = 1;
            public const uint WM_LBUTTONDOWN = 0x201;
            public const uint WM_LBUTTONUP = 0x202;

            [DllImport("kernel32.dll")]
            public static extern int CloseHandle(IntPtr hObject);
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool CreateProcess(string imageName, string cmdLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool boolInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpszCurrentDir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);
            [DllImport("user32.dll", SetLastError=true)]
            public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
            [DllImport("user32.dll")]
            public static extern bool FlashWindow(IntPtr hWnd, bool invert);
            public static IntPtr GetBaseAddress(IntPtr hProcess) {
                SYSTEM_INFO system_info;
                GetSystemInfo(out system_info);
                IntPtr lpMinimumApplicationAddress = system_info.lpMinimumApplicationAddress;
                MEMORY_BASIC_INFORMATION structure = new MEMORY_BASIC_INFORMATION();
                uint dwLength = (uint) Marshal.SizeOf(structure);
                while (lpMinimumApplicationAddress.ToInt64() < system_info.lpMaximumApplicationAddress.ToInt64()) {
                    if (!VirtualQueryEx(hProcess, lpMinimumApplicationAddress, out structure, dwLength)) {
                        Console.WriteLine("Could not VirtualQueryEx {0} segment at {1}; error {2}", hProcess.ToInt64(), lpMinimumApplicationAddress.ToInt64(), Marshal.GetLastWin32Error());
                        return IntPtr.Zero;
                    }
                    if (((structure.Type == 0x1000000) && (structure.BaseAddress == structure.AllocationBase)) && ((structure.Protect & 0x100) != 0x100)) {
                        IMAGE_DOS_HEADER image_dos_header = ReadUnmanagedStructure<IMAGE_DOS_HEADER>(hProcess, lpMinimumApplicationAddress);
                        if (image_dos_header.e_magic == 0x5a4d) {
                            IntPtr lpAddr = new IntPtr(lpMinimumApplicationAddress.ToInt64() + (image_dos_header.e_lfanew + 4));
                            if ((ReadUnmanagedStructure<IMAGE_FILE_HEADER>(hProcess, lpAddr).Characteristics & 2) == 2) {
                                return lpMinimumApplicationAddress;
                            }
                        }
                    }
                    long introduced6 = structure.BaseAddress.ToInt64();
                    lpMinimumApplicationAddress = new IntPtr(introduced6 + structure.RegionSize.ToInt64());
                }
                return lpMinimumApplicationAddress;
            }

            [DllImport("user32.dll", CharSet=CharSet.Auto)]
            public static extern int GetClassName(IntPtr hWnd, StringBuilder className, int maxCharCount);
            [DllImport("user32.dll")]
            public static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);
            [DllImport("user32.dll")]
            public static extern IntPtr GetForegroundWindow();
            [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);
            [DllImport("kernel32.dll", CharSet=CharSet.Ansi, ExactSpelling=true)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            [DllImport("kernel32.dll")]
            public static extern void GetSystemInfo([MarshalAs(UnmanagedType.Struct)] out SYSTEM_INFO lpSystemInfo);
            [DllImport("user32.dll")]
            public static extern IntPtr GetWindowRect(IntPtr hWnd, ref RECT rect);
            [DllImport("user32.dll")]
            public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
            [DllImport("user32.dll", SetLastError=true)]
            public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);
            [DllImport("user32.dll")]
            public static extern bool IsIconic(IntPtr hWnd);
            [DllImport("user32.dll")]
            public static extern bool IsZoomed(IntPtr hWnd);
            public static int MakeLParam(int LoWord, int HiWord) {
                return ((HiWord << 0x10) | (LoWord & 0xffff));
            }

            public static int MakeWParam(int LoWord, int HiWord) {
                return ((HiWord << 0x10) | (LoWord & 0xffff));
            }

            [DllImport("kernel32.dll")]
            public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
            [DllImport("kernel32.dll")]
            public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);
            [DllImport("kernel32.dll")]
            public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesRead);
            [return: MarshalAs(UnmanagedType.Bool)]
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);
            public static T ReadUnmanagedStructure<T>(IntPtr hProcess, IntPtr lpAddr) {
                byte[] lpBuffer = new byte[Marshal.SizeOf(typeof(T))];
                ReadProcessMemory(hProcess, lpAddr, lpBuffer, new UIntPtr((uint) lpBuffer.Length), IntPtr.Zero);
                GCHandle handle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
                T local = (T) Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                handle.Free();
                return local;
            }

            [DllImport("kernel32.dll")]
            public static extern uint ResumeThread(IntPtr hThread);
            [DllImport("user32.dll")]
            public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, int wParam, int lParam);
            [DllImport("user32.dll")]
            public static extern bool SetForegroundWindow(IntPtr hWnd);
            [DllImport("user32.dll")]
            public static extern bool SetWindowPos(IntPtr hWnd, uint hWndInsertAfter, int x, int y, int cx, int cy, uint uFlags);
            [DllImport("user32.dll")]
            public static extern void SetWindowText(IntPtr hWnd, string str);
            [DllImport("user32.dll")]
            public static extern bool ShowWindow(IntPtr hWnd, int nCmd);
            [DllImport("kernel32.dll", SetLastError=true, ExactSpelling=true)]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
            [DllImport("kernel32.dll", SetLastError=true, ExactSpelling=true)]
            public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType dwFreeType);
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, MemoryProtection flNewProtect, ref MemoryProtection lpflOldProtect);
            [DllImport("kernel32.dll")]
            public static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern int WaitForSingleObject(IntPtr Handle, uint Wait);
            [DllImport("kernel32.dll")]
            public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesWritten);

            [Flags]
            public enum AllocationType {
                Commit = 0x1000,
                Decommit = 0x4000,
                LargePages = 0x20000000,
                Physical = 0x400000,
                Release = 0x8000,
                Reserve = 0x2000,
                Reset = 0x80000,
                TopDown = 0x100000,
                WriteWatch = 0x200000
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DOS_HEADER {
                public ushort e_magic;
                public ushort e_cblp;
                public ushort e_cp;
                public ushort e_crlc;
                public ushort e_cparhdr;
                public ushort e_minalloc;
                public ushort e_maxalloc;
                public ushort e_ss;
                public ushort e_sp;
                public ushort e_csum;
                public ushort e_ip;
                public ushort e_cs;
                public ushort e_lfarlc;
                public ushort e_ovno;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst=4)]
                public ushort[] e_res1;
                public ushort e_oemid;
                public ushort e_oeminfo;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst=10)]
                public ushort[] e_res2;
                public int e_lfanew;
            }

            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct IMAGE_FILE_HEADER {
                public ushort Machine;
                public ushort NumberOfSections;
                public uint TimeDateStamp;
                public uint PointerToSymbolTable;
                public uint NumberOfSymbols;
                public ushort SizeOfOptionalHeader;
                public ushort Characteristics;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MEMORY_BASIC_INFORMATION {
                public IntPtr BaseAddress;
                public IntPtr AllocationBase;
                public uint AllocationProtect;
                public IntPtr RegionSize;
                public uint State;
                public uint Protect;
                public uint Type;
            }

            [Flags]
            public enum MemoryProtection {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                GuardModifierflag = 0x100,
                NoAccess = 1,
                NoCacheModifierflag = 0x200,
                ReadOnly = 2,
                ReadWrite = 4,
                WriteCombineModifierflag = 0x400,
                WriteCopy = 8
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MODULEENTRY32 {
                public uint dwSize;
                public uint th32ModuleID;
                public uint th32ProcessID;
                public uint GlblcntUsage;
                public uint ProccntUsage;
                private IntPtr modBaseAddr;
                public uint modBaseSize;
                private IntPtr hModule;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst=0x100)]
                public string szModule;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)]
                public string szExePath;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION {
                public IntPtr hProcess;
                public IntPtr hThread;
                public uint dwProcessId;
                public uint dwThreadId;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct RECT {
                public int left;
                public int top;
                public int right;
                public int bottom;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES {
                public int length;
                public IntPtr lpSecurityDescriptor;
                public bool bInheritHandle;
            }

            [Flags]
            public enum SnapshotFlags : uint {
                All = 15,
                HeapList = 1,
                Inherit = 0x80000000,
                Module = 8,
                Module32 = 0x10,
                NoHeaps = 0x40000000,
                Process = 2,
                Thread = 4
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct STARTUPINFO {
                public uint cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public uint dwX;
                public uint dwY;
                public uint dwXSize;
                public uint dwYSize;
                public uint dwXCountChars;
                public uint dwYCountChars;
                public uint dwFillAttribute;
                public uint dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SYSTEM_INFO {
                public ushort processorArchitecture;
                private ushort reserved;
                public uint dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public IntPtr dwActiveProcessorMask;
                public uint dwNumberOfProcessors;
                public uint dwProcessorType;
                public uint dwAllocationGranularity;
                public ushort dwProcessorLevel;
                public ushort dwProcessorRevision;
            }
        }
    }
}