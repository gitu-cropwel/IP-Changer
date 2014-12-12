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

namespace IP_Changer {
    public class IPChanger : Form {
        private String RSA = "109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413";
        private Button button1;
        private CheckBox checkBox1;
        private IContainer components;
        private Label label1;
        private Label label2;
        private LinkLabel linkLabel1;
        private TextBox textBox1;
        private TextBox textBox2;
        public IntPtr ProcessHandle;
        public int selectedClient = 0;

        public IPChanger() {
            this.InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e) {
            if (this.textBox1.Text.Length < 1) {
                MessageBox.Show("Please enter an IP address.", "Error.", MessageBoxButtons.OK);
            } else {
                Process[] processesByName = Process.GetProcessesByName("Tibia");
                if (processesByName.Length < 1) {
                    MessageBox.Show("Please start Tibia first.", "Error.", MessageBoxButtons.OK);
                } else {
                    long[] rsaAdress = new long[] { 0x385970L, 0x373810L, 0x372800L, 0x36f7f0L, 0x33a450L, 0x1b8980L };
                    long[] numArray2 = new long[] { 0x48A094L, 0x46885cL, 0x46885cL, 0x461738L, 0x41c568L, 0x3947f8L }; // ADRESSES OF STATIC TIBIA IP
                    long[] numArray3 = new long[] { 0x48A098L, 0x468860L, 0x468860L, 0x46173cL, 0x41c56cL, 0L };
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
                    string[] strArray = new string[] { "10.6.3.0", "10.5.4.0", "10.5.3.0", "10.4.1.0", "10.3.7.0", "8.60" };
                    string[] source = new string[] { "10.5.0.0", "10.5.1.0", "10.5.2.0" };
                    int length = strArray.Length - 1;
                    short index = 0;
                    foreach (Process process in processesByName) {
                        this.ProcessHandle = WinApi.OpenProcess(0x1f0fff, 0, (uint) process.Id);
                        this.BaseAddress = WinApi.GetBaseAddress(this.ProcessHandle).ToInt64();

                        //Reading Tibia Version and checking
                        string str = process.MainModule.FileVersionInfo.FileVersion.ToString();
                        if (strArray.Contains<String>(str)) {
                            for (int i = 0; i < length; i++) {
                                if (strArray[i] == str) {
                                    if(i >= 3)
                                        selectedClient = i + 1;
                                    else
                                        selectedClient = i;
                                }
                            }
                        } else if(source.Contains<String>(str)) {
                            selectedClient = 3;
                        } else {
                            MessageBox.Show("This Tibia Client is not supported!", "Error", MessageBoxButtons.OK);
                            break;
                        }

                        //MessageBox.Show("Tibia Client: " + str + " Base: " + this.BaseAddress + "", "Error", MessageBoxButtons.OK);

                        int num2 = int.Parse(str.Replace(".", ""));
                        if ((num2 >= 0x2774) && (num2 < 0x2904)) {
                            index = 1;
                        } else if (num2 == 860) {
                            index = 2;
                        }

                        WinApi.SetWindowText(process.MainWindowHandle, "Tibia - " + this.textBox1.Text + ":" + this.textBox2.Text);
                        WinApi.SetForegroundWindow(process.MainWindowHandle);

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
                        uint num5 = Memory.ReadUInt32(this.ProcessHandle, (long) ptr);
                        Memory.ReadUInt32(this.ProcessHandle, (long) ptr2);
                        int num1 = numArray4[index];
                        uint num6 = num5;
                        uint num7 = Memory.ReadUInt32(this.ProcessHandle, num6 + numArray6[index]);
                        if (num7 != 0) {
                            uint num8 = num6 + ((uint) numArray7[index]);
                            Memory.WriteInt16(this.ProcessHandle, (long) num8, (short) int.Parse(this.textBox2.Text.Trim()));
                            int num9 = BitConverter.ToInt32(IPAddress.Parse(Dns.GetHostAddresses(this.textBox1.Text.Trim())[0].ToString()).GetAddressBytes(), 0);
                            Memory.WriteInt32(this.ProcessHandle, (long) num7, num9);
                            uint num10 = Memory.ReadUInt32(this.ProcessHandle, num6 + numArray5[index]);
                            Memory.WriteString(this.ProcessHandle, (long)num10, this.textBox1.Text.Trim());
                        }
                        WinApi.CloseHandle(this.ProcessHandle);
                    }
                }
            }
        }

        protected override void Dispose(bool disposing) {
            if (disposing && (this.components != null)) {
                this.components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent() {
            ComponentResourceManager manager = new ComponentResourceManager(typeof(IPChanger));
            this.button1 = new Button();
            this.textBox1 = new TextBox();
            this.label1 = new Label();
            this.textBox2 = new TextBox();
            this.label2 = new Label();
            this.linkLabel1 = new LinkLabel();
            this.checkBox1 = new CheckBox();
            base.SuspendLayout();

            this.button1.Location = new Point(247, 4);
            this.button1.Name = "button1";
            this.button1.Size = new Size(0x38, 0x17);
            this.button1.TabIndex = 3;
            this.button1.Text = "Change";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new EventHandler(this.button1_Click);

            //IP
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
            this.textBox1.Text = "reptera.net";

            //PORT
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

            this.linkLabel1.AutoSize = true;
            this.linkLabel1.LinkBehavior = LinkBehavior.HoverUnderline;
            this.linkLabel1.Location = new Point(1, 30);
            this.linkLabel1.Name = "linkLabel1";
            this.linkLabel1.Size = new Size(0x36, 13);
            this.linkLabel1.TabIndex = 9;
            this.linkLabel1.TabStop = true;
            this.linkLabel1.Text = "Github Source Code";
            this.linkLabel1.VisitedLinkColor = Color.Blue;
            this.linkLabel1.LinkClicked += new LinkLabelLinkClickedEventHandler(this.linkLabel1_LinkClicked);

            this.checkBox1.AutoSize = true;
            this.checkBox1.Enabled = false;
            this.checkBox1.Location = new Point(0xb3, 0x3b);
            this.checkBox1.Name = "checkBox1";
            this.checkBox1.Size = new Size(0x4a, 0x11);
            this.checkBox1.TabIndex = 10;
            this.checkBox1.Text = "MultiClient";
            this.checkBox1.UseVisualStyleBackColor = true;
            this.checkBox1.Visible = false;

            //Create Window
            base.AutoScaleDimensions = new SizeF(6f, 13f);
            base.AutoScaleMode = AutoScaleMode.Font;
            base.ClientSize = new Size(0x135, 0x30);
            base.Controls.Add(this.checkBox1);
            base.Controls.Add(this.linkLabel1);
            base.Controls.Add(this.textBox2);
            base.Controls.Add(this.label1);
            base.Controls.Add(this.label2);
            base.Controls.Add(this.textBox1);
            base.Controls.Add(this.button1);
            base.FormBorderStyle = FormBorderStyle.FixedDialog;
            base.MaximizeBox = false;
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