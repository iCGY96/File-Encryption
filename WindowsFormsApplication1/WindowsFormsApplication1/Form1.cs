using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
struct processKey
{
    public int enbe;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public uint[] key;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 200)]
    public string fileOpen;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 200)]
    public string fileSave;
}

[StructLayout(LayoutKind.Sequential)]
struct RijndaelprocessKey
{
    public int enbe;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] key;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 100)]
    public string fileOpen;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 100)]
    public string fileSave;
}

namespace WindowsFormsApplication1
{
    public partial class SM4文件加密软件 : Form
    {
        [DllImport("Rijndael.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RijndaelProccess(IntPtr block);

        [DllImport("ShaderModel4.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ShaderModel4Proccess(IntPtr block);

        //public static extern int sum(int a, int b);
        //0123456789abcdeffedcba9876543210

        public bool check = false, checkStyle = false, style = true;
        public int en_be = 1;

        public SM4文件加密软件()
        {
            InitializeComponent();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void 开始_Click(object sender, EventArgs e)
        {
            char[] key = textBox1.Text.ToCharArray();

            int size1 = Marshal.SizeOf(typeof(processKey));
            processKey pClass1 = new processKey();

            int size2 = Marshal.SizeOf(typeof(RijndaelprocessKey));
            RijndaelprocessKey pClass2 = new RijndaelprocessKey();
            IntPtr pBuff;

            if (style == false)
            {
                pBuff = Marshal.AllocHGlobal(size2);
                byte[] keyW = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                byte temp;
                for (int i = 0; i < 32; i++)
                {
                    temp = 0;
                    if (key[i] >= 48 && key[i] <= 57)
                        temp = (byte)(key[i] - 48);
                    else if (key[i] >= 65 && key[i] <= 70)
                        temp = (byte)(key[i] - 55);
                    else if (key[i] >= 97 && key[i] <= 102)
                        temp = (byte)(key[i] - 87);
                    else
                    {
                        MessageBox.Show("请输入正确密钥", "ERROR");
                        break;
                    }

                    if(i % 2 == 0)  temp = (byte)(temp << 4);
                    keyW[i / 2] = (byte)(temp | keyW[i / 2]);
                }
                pClass2.enbe = en_be;

                /*
                if (pClass2.enbe == 1)
                    MessageBox.Show("加密", "ERROR");
                else
                    MessageBox.Show("解密", "ERROR");*/

                pClass2.key = new byte[16] { keyW[0], keyW[1], keyW[2], keyW[3], keyW[4], keyW[5], keyW[6], keyW[7], keyW[8], keyW[9], keyW[10], keyW[11], keyW[12], keyW[13], keyW[14], keyW[15] };
                /*
                if (pClass2.key[0] == 0x01 && pClass2.key[1] == 0x23 && pClass2.key[2] == 0x45 && pClass2.key[3] == 0x67 && pClass2.key[4] == 0x89 && pClass2.key[5] == 0xab && pClass2.key[6] == 0xcd && pClass2.key[7] == 0xef && pClass2.key[8] == 0xfe && pClass2.key[9] == 0xdc && pClass2.key[10] == 0xba && pClass2.key[11] == 0x98 && pClass2.key[12] == 0x76 && pClass2.key[13] == 0x54 && pClass2.key[14] == 0x32 && pClass2.key[15] == 0x10)
                    MessageBox.Show("key", "ERROR");*/

                pClass2.fileOpen = string.Copy(textBox2.Text);
                //MessageBox.Show(pClass2.fileOpen);
                pClass2.fileSave = string.Copy(textBox3.Text);
                //MessageBox.Show(pClass2.fileSave);

                Marshal.StructureToPtr(pClass2, pBuff, true);
            }
            else
            {
                pBuff = Marshal.AllocHGlobal(size1);
                uint[] keyW = new uint[4] { 0, 0, 0, 0};
                uint temp;

                for (int i = 0; i < 32; i ++)
                {
                    temp = 0;
                    if (key[i] >= 48 && key[i] <= 57)
                        temp = (uint)key[i] - 48;
                    else if (key[i] >= 65 && key[i] <= 70)
                        temp = (uint)key[i] - 55;
                    else if (key[i] >= 97 && key[i] <= 102)
                        temp = (uint)key[i] - 87;
                    else
                    {
                        MessageBox.Show("请输入正确密钥", "ERROR");
                        break;
                    }

                    temp = temp << ((7 - i%8) * 4);
                    keyW[i / 8] = temp | keyW[ i / 8];
                }

                pClass1.enbe = en_be;
                pClass1.key = new uint[] { keyW[0], keyW[1], keyW[2], keyW[3] };
                pClass1.fileOpen = string.Copy(textBox2.Text);
                pClass1.fileSave = string.Copy(textBox3.Text);

                Marshal.StructureToPtr(pClass1, pBuff, true);
            }

            if (textBox1.TextLength < 32)
                MessageBox.Show("请输入正确密钥", "ERROR");
            else if (textBox2.TextLength < 4)
                MessageBox.Show("请选择加密文件", "ERROR");
            else if (textBox3.TextLength < 4)
                MessageBox.Show("请选择保存地址", "ERROR");
            else if (check == false)
                MessageBox.Show("请选择加密/解密", "ERROR");
            else if (checkStyle == false)
                MessageBox.Show("请选择加密/解密方式", "ERROR");
            else if (en_be == 1 && style == true && ShaderModel4Proccess(pBuff) == 1)
                MessageBox.Show("文件加密成功");
            else if (en_be == 0 && style == true && ShaderModel4Proccess(pBuff) == 1)
                MessageBox.Show("文件解密成功");
            else if (style == false)
            {
                //MessageBox.Show("AES");
                if (RijndaelProccess(pBuff) == 1)
                {
                    if (RijndaelProccess(pBuff) == 1)
                        if (en_be == 1)
                            MessageBox.Show("文件加密成功");
                        else
                            MessageBox.Show("文件解密成功");
                }   
            }
            else
                MessageBox.Show("文件加载失败");

            Marshal.FreeHGlobal(pBuff);
            //MessageBox.Show("OKOOOOO");
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog file1 = new OpenFileDialog();
            file1.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyComputer);
            file1.Filter = "所有文件(*.*)|*.*";
            if (file1.ShowDialog(this) == DialogResult.OK)
            {
                string inFileName = file1.FileName;

                textBox2.Text = inFileName;
            }
        }

        private void button2_Click_1(object sender, EventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            saveFileDialog.Filter = "所有文件(*.*)|*.*";
            if (saveFileDialog.ShowDialog(this) == DialogResult.OK)
            {
                string outFileName = saveFileDialog.FileName;

                textBox3.Text = outFileName;
            }
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            en_be = 1; check = true;
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            en_be = 0;  check = true;
        }

        private void radioButton3_CheckedChanged(object sender, EventArgs e)
        {
            style = false; checkStyle = true;
        }

        private void radioButton4_CheckedChanged(object sender, EventArgs e)
        {
            style = true; checkStyle = true;
        }
    }
}
