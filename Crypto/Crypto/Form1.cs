using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Web;
using System.Text.RegularExpressions;

namespace Crypto
{

    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button7_Click(object sender, EventArgs e)//md5选择文件
        {
            OpenFileDialog openFile1 = new OpenFileDialog();
            openFile1.RestoreDirectory = true;
            if (openFile1.ShowDialog() == DialogResult.OK)
            {
                textBox3.Text = openFile1.FileName.ToString();
            }
        }

        private void button10_Click(object sender, EventArgs e)//sha1选择文件
        {
            OpenFileDialog openFile2 = new OpenFileDialog();
            openFile2.RestoreDirectory = true;
            if (openFile2.ShowDialog() == DialogResult.OK)
            {
                textBox5.Text = openFile2.FileName.ToString();
            }
        }

        private void radioButton9_CheckedChanged(object sender, EventArgs e)//新的RSA选择加密，隐藏控件
        {
            if (radioButton9.Checked == true)
            {
                label24.Show();
                richTextBox17.Show();
                button18.Show();

                label21.Hide();
                richTextBox16.Hide();
                button17.Hide();
            }
            else
            {
                label24.Hide();
                richTextBox17.Hide();
                button18.Hide();

                label21.Show();
                richTextBox16.Show();
                button17.Show();
            }
        }

        private void button1_Click(object sender, EventArgs e)//AES加密
        {
            int AES_Checked = 0;
            if (radioButton1.Checked == true) AES_Checked = 1;
            else if (radioButton2.Checked == true) AES_Checked = 2;
            else if (radioButton3.Checked == true) AES_Checked = 3;

            string AES_Key = textBox1.Text;
            string AES_IV = textBox8.Text;
            int[] AES_Length = { 16, 24, 32 };
            if (AES_Key.Length != AES_Length[AES_Checked - 1]) { MessageBox.Show("密钥应为" + AES_Length[AES_Checked - 1] + "位"); return; }//密钥长度
            if (AES_IV.Length != 16) { MessageBox.Show("向量应为16位"); return; }
            CipherMode AES_Mode = CipherMode.ECB;
            if (radioButton4.Checked == true) AES_Mode = CipherMode.ECB;
            else if (radioButton5.Checked == true) AES_Mode = CipherMode.CBC;
            else if (radioButton7.Checked == true) AES_Mode = CipherMode.CFB;

            int pad = comboBox3.SelectedIndex;

            string AES_Message = richTextBox2.Text;
            if (AES_Message == "" || AES_Message == null) return;
            string AES_Ciphertext = MyAES.Encrypt(AES_Message, AES_Key, AES_IV, AES_Mode, pad, AES_Length[AES_Checked - 1] * 8);
            richTextBox1.Text = AES_Ciphertext;

        }

        private void button2_Click(object sender, EventArgs e)//AES解密
        {

            int AES_Checked = 0;
            if (radioButton1.Checked == true) AES_Checked = 1;
            else if (radioButton2.Checked == true) AES_Checked = 2;
            else if (radioButton3.Checked == true) AES_Checked = 3;

            string AES_Key = textBox1.Text;
            string AES_IV = textBox8.Text;
            int[] AES_Length = { 16, 24, 32 };
            if (AES_Key.Length != AES_Length[AES_Checked - 1]) { MessageBox.Show("密钥应为" + AES_Length[AES_Checked - 1] + "位"); return; }//密钥长度
            if (AES_IV.Length != 16) { MessageBox.Show("向量应为16位"); return; }
            CipherMode AES_Mode = CipherMode.ECB;
            if (radioButton4.Checked == true) AES_Mode = CipherMode.ECB;
            else if (radioButton5.Checked == true) AES_Mode = CipherMode.CBC;
            else if (radioButton7.Checked == true) AES_Mode = CipherMode.CFB;

            int pad = comboBox3.SelectedIndex;

            string AES_Ciphertext = richTextBox1.Text;
            if (AES_Ciphertext == "" || AES_Ciphertext == null) return;
            string AES_Message = MyAES.Decrypt(AES_Ciphertext, AES_Key, AES_IV, AES_Mode, pad, AES_Length[AES_Checked - 1] * 8);
            richTextBox2.Text = AES_Message;
        }

        private void button3_Click(object sender, EventArgs e)//DES加密
        {
            int pad = comboBox2.SelectedIndex;
            CipherMode DES_Mode = CipherMode.ECB;
            if (radioButton15.Checked == true) DES_Mode = CipherMode.ECB;
            else if (radioButton16.Checked == true) DES_Mode = CipherMode.CBC;
            else if (radioButton17.Checked == true) DES_Mode = CipherMode.CFB;

            string DES_Key = textBox2.Text;
            string DES_IV = textBox9.Text;
            if (DES_IV.Length != 8) { MessageBox.Show("向量应为8位"); return; }
            if (DES_Key.Length != 8) { MessageBox.Show("密钥位数应为8位"); return; }//密钥长度
            string DES_Message = richTextBox3.Text;
            if (DES_Message == "" || DES_Message == null) return;

            richTextBox4.Text = MyDES.Encrypt(DES_Message, DES_Key, DES_IV, DES_Mode, pad);
        }

        private void button4_Click(object sender, EventArgs e)//DES解密
        {
            int pad = comboBox2.SelectedIndex;
            CipherMode DES_Mode = CipherMode.ECB;
            if (radioButton15.Checked == true) DES_Mode = CipherMode.ECB;
            else if (radioButton16.Checked == true) DES_Mode = CipherMode.CBC;
            else if (radioButton17.Checked == true) DES_Mode = CipherMode.CFB;
            string DES_Key = textBox2.Text;
            string DES_IV = textBox9.Text;

            if (DES_Key.Length != 8) { MessageBox.Show("密钥位数与算法不匹配"); return; }//密钥长度

            string DES_Ciphertext = richTextBox4.Text;
            if (DES_Ciphertext == "" || DES_Ciphertext == null) return;
            string DES_Message = MyDES.Decrypt(DES_Ciphertext, DES_Key, DES_IV, DES_Mode, pad);
            richTextBox3.Text = DES_Message;
        }

        private void button15_Click(object sender, EventArgs e)//Base64加密
        {
            Encoding encoding = Encoding.UTF8;
            int t = comboBox1.SelectedIndex;
            switch (t)
            {
                case 0: encoding = Encoding.UTF8; break;
                case 1: encoding = Encoding.GetEncoding("GB2312"); break;
                case 2: encoding = Encoding.GetEncoding("GBK"); break;
                case 3: encoding = Encoding.ASCII; break;
                case 4: encoding = Encoding.Unicode; break;
                case 5: encoding = Encoding.UTF7; break;
                case 6: encoding = Encoding.UTF32; break;
                case 7: encoding = Encoding.BigEndianUnicode; break;
                default: encoding = Encoding.UTF8; break;
            }
            string decode_Num = textBox14.Text;
            int num = 1;
            int.TryParse(decode_Num, out num);
            if (num < 1)
            {
                num = 1;
            }
            string Base64_Message = richTextBox13.Text;
            for (int i = 0; i < num; i++)
            {
                Base64_Message = MyBase64.EncodeBase64(Base64_Message, encoding);
            }

            richTextBox14.Text = Base64_Message;

        }

        private void button14_Click(object sender, EventArgs e)//Base64解密
        {

            Encoding encoding = Encoding.UTF8;

            int t = comboBox1.SelectedIndex;
            switch (t)
            {
                case 0: encoding = Encoding.UTF8; break;
                case 1: encoding = Encoding.GetEncoding("GB2312"); break;
                case 2: encoding = Encoding.GetEncoding("GBK"); break;
                case 3: encoding = Encoding.ASCII; break;
                case 4: encoding = Encoding.Unicode; break;
                case 5: encoding = Encoding.UTF7; break;
                case 6: encoding = Encoding.UTF32; break;
                case 7: encoding = Encoding.BigEndianUnicode; break;
                default: encoding = Encoding.UTF8; break;
            }
            
            string decode_Num = textBox14.Text;
            int num = 1;
            int.TryParse(decode_Num, out num);
            if (num < 1) {
                num = 1;
            }

            bool url_decode_flag = checkBox1.Checked;
            string Base64_Ciphertext = richTextBox14.Text;
            for (int i = 0; i < num; i++) {
                if (url_decode_flag) {
                    Base64_Ciphertext = MyUrl.Decode(Base64_Ciphertext, encoding);
                }
                Base64_Ciphertext = MyBase64.DecodeBase64(Base64_Ciphertext, encoding);
            }

            richTextBox13.Text = Base64_Ciphertext;
        }

        private void button8_Click(object sender, EventArgs e)//MD5文字
        {
            string MD5_Message = richTextBox10.Text.Trim();
            if (MD5_Message == "") { textBox4.Text = ""; return; }
            bool MD5_Mode = radioButton11.Checked;
            textBox4.Text = MyMD5.GetMD5Hash(MD5_Message, MD5_Mode);


        }

        private void button9_Click(object sender, EventArgs e)//MD5文件
        {
            string FilePath = textBox3.Text.Trim();
            if (FilePath == null || FilePath == "") return;
            if (File.Exists(FilePath) != true)
            {
                MessageBox.Show("文件不存在");
                return;
            }
            bool MD5_Mode = radioButton11.Checked;
            textBox4.Text = MyMD5.GetMD5HashFromFile(FilePath, MD5_Mode);
        }

        private void button11_Click(object sender, EventArgs e)//SHA1文字
        {
            string SHA1_Message = richTextBox11.Text.Trim();
            if (SHA1_Message == null || SHA1_Message == "") return;
            string[] sha = MySHA.GetSHAHash(SHA1_Message);
            textBox6.Text = sha[0];
            textBox10.Text = sha[1];
            textBox11.Text = sha[2];
            textBox12.Text = sha[3];

        }

        private void button12_Click(object sender, EventArgs e)//SHA1文件
        {
            string FilePath = textBox5.Text.Trim();
            if (FilePath == null || FilePath == "") return;
            if (File.Exists(FilePath) != true)
            {
                MessageBox.Show("文件不存在");
                return;
            }
            string[] sha = MySHA.GetSHAHashFromFile(FilePath);
            textBox6.Text = sha[0];
            textBox10.Text = sha[1];
            textBox11.Text = sha[2];
            textBox12.Text = sha[3];
        }

        private void button16_Click(object sender, EventArgs e)//生成RSA密钥
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string publickey = rsa.ToXmlString(false);
            string privatekey = rsa.ToXmlString(true);
            richTextBox16.Text = privatekey;
            richTextBox17.Text = publickey;
        }

        private void button17_Click(object sender, EventArgs e)//RSA解密
        {
            bool RSA_Mode = radioButton13.Checked;
            string RSA_Ciphertext = richTextBox12.Text;
            richTextBox15.Text = "";
            string privatekey = richTextBox16.Text;
            byte[] ciphertext = new byte[RSA_Ciphertext.Length / 2];
            try
            {
                for (int x = 0; x < RSA_Ciphertext.Length / 2; x++)
                {
                    int i = (Convert.ToInt32(RSA_Ciphertext.Substring(x * 2, 2), 16));
                    ciphertext[x] = (byte)i;
                }
            }
            catch { MessageBox.Show("密文不正确！"); }
            byte[] source;    //原文byte数组
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            try
            {
                rsa.FromXmlString(privatekey);                          //设置私钥
                source = rsa.Decrypt(ciphertext, RSA_Mode);                    //解密，得到byte数组
                richTextBox15.Text = Encoding.Default.GetString(source);    //返回结果
            }
            catch { MessageBox.Show("密钥不正确"); }

        }

        private void button18_Click(object sender, EventArgs e)//RSA加密
        {
            bool RSA_Mode = radioButton13.Checked;
            string RSA_Message = richTextBox15.Text;
            richTextBox12.Text = "";
            byte[] source = Encoding.Default.GetBytes(RSA_Message);      //明文转换为byte
            byte[] ciphertext;                                           //密文byte数组
            string publickey = richTextBox17.Text;                       //string密钥
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            try
            {
                rsa.FromXmlString(publickey);                                //导入string密钥  
                ciphertext = rsa.Encrypt(source, RSA_Mode);                       //加密
                StringBuilder sb = new StringBuilder();
                foreach (byte b in ciphertext)
                {
                    sb.AppendFormat("{0:X2}", b);
                }
                richTextBox12.Text = sb.ToString();



            }
            catch { MessageBox.Show("加密失败，请检查密钥"); }
        }

        private void button6_Click(object sender, EventArgs e)//URL解码
        {
            Encoding encoding = Encoding.UTF8;

            int t = comboBox4.SelectedIndex;
            switch (t)
            {
                case 0: encoding = Encoding.UTF8; break;
                case 1: encoding = Encoding.GetEncoding("GB2312"); break;
                case 2: encoding = Encoding.GetEncoding("GBK"); break;
                case 3: encoding = Encoding.ASCII; break;
                case 4: encoding = Encoding.Unicode; break;
                case 5: encoding = Encoding.UTF7; break;
                case 6: encoding = Encoding.UTF32; break;
                case 7: encoding = Encoding.BigEndianUnicode; break;
                default: encoding = Encoding.UTF8; break;
            }
            richTextBox5.Text = MyUrl.Decode(richTextBox6.Text, encoding);
        }

        private void button5_Click(object sender, EventArgs e)//URL部分编码
        {
            Encoding encoding = Encoding.ASCII;

            int t = comboBox4.SelectedIndex;
            switch (t)
            {
                case 0: encoding = Encoding.UTF8; break;
                case 1: encoding = Encoding.GetEncoding("GB2312"); break;
                case 2: encoding = Encoding.GetEncoding("GBK"); break;
                case 3: encoding = Encoding.ASCII; break;
                case 4: encoding = Encoding.Unicode; break;
                case 5: encoding = Encoding.UTF7; break;
                case 6: encoding = Encoding.UTF32; break;
                case 7: encoding = Encoding.BigEndianUnicode; break;
                default: encoding = Encoding.UTF8; break;
            }
            richTextBox6.Text = MyUrl.Encode(richTextBox5.Text, encoding);
        }

        private void button20_Click(object sender, EventArgs e)//URL二次解码
        {
            Encoding encoding = Encoding.ASCII;

            int t = comboBox4.SelectedIndex;
            switch (t)
            {
                case 0: encoding = Encoding.UTF8; break;
                case 1: encoding = Encoding.GetEncoding("GB2312"); break;
                case 2: encoding = Encoding.GetEncoding("GBK"); break;
                case 3: encoding = Encoding.ASCII; break;
                case 4: encoding = Encoding.Unicode; break;
                case 5: encoding = Encoding.UTF7; break;
                case 6: encoding = Encoding.UTF32; break;
                case 7: encoding = Encoding.BigEndianUnicode; break;
                default: encoding = Encoding.UTF8; break;
            }
            richTextBox5.Text = MyUrl.Decode(MyUrl.Decode(richTextBox6.Text, encoding), encoding);
        }

        private void button21_Click(object sender, EventArgs e)//URL二次部分编码
        {
            Encoding encoding = Encoding.ASCII;
            int t = comboBox4.SelectedIndex;
            switch (t)
            {
                case 0 : encoding = Encoding.UTF8; break;
                case 1: encoding = Encoding.GetEncoding("GB2312"); break;
                case 2: encoding = Encoding.GetEncoding("GBK"); break;
                case 3: encoding = Encoding.ASCII; break;
                case 4: encoding = Encoding.Unicode; break;
                case 5: encoding = Encoding.UTF7; break;
                case 6: encoding = Encoding.UTF32; break;
                case 7: encoding = Encoding.BigEndianUnicode; break;
                default: encoding = Encoding.UTF8; break;
    }
            richTextBox6.Text = MyUrl.Encode(MyUrl.Encode(richTextBox5.Text, encoding),encoding);
        }

        private void button19_Click(object sender, EventArgs e)//html编码
        {
            bool flag = true;
            if (radioButton6.Checked) {//10进制
                flag = true;
            }else//16进制
            {
                flag = false;
            }
            richTextBox7.Text = MyHtml.Encode(richTextBox8.Text,flag);
        }

        private void button13_Click(object sender, EventArgs e)//html解码
        {
           
            richTextBox8.Text = MyHtml.Decode(richTextBox7.Text);
        }

        private void button28_Click(object sender, EventArgs e)//转16进制
        {
            Encoding encoding = Encoding.ASCII;
            int t = comboBox5.SelectedIndex;
            switch (t)
            {
                case 0: encoding = Encoding.ASCII; break;
                case 1: encoding = Encoding.Unicode; break;
                case 2: encoding = Encoding.UTF8; break;
                case 3: encoding = Encoding.GetEncoding("gb2312"); break;
                default: encoding = Encoding.ASCII; break;
            }

            String originalText = richTextBox18.Text;
            richTextBox9.Text = "";
            byte[] originalByte = encoding.GetBytes(originalText);
            String outString = "";
            foreach (byte tmpByte in originalByte) {
                outString += String.Format(" {0:X2}", Convert.ToInt32(tmpByte));
            }

            richTextBox9.Text = outString;


        }

        private void button29_Click(object sender, EventArgs e)//转字符串
        {
            Encoding encoding = Encoding.ASCII;
            int t = comboBox5.SelectedIndex;
            switch (t)
            {
                case 0: encoding = Encoding.ASCII; break;
                case 1: encoding = Encoding.Unicode; break;
                case 2: encoding = Encoding.UTF8; break;
                case 3: encoding = Encoding.GetEncoding("gb2312"); break;
                default: encoding = Encoding.ASCII; break;
            }

            String originalText = richTextBox18.Text.Replace(" ","");
            richTextBox9.Text = "";
            try
            {
                byte[] bs = new byte[originalText.Length / 2 + originalText.Length%2];
                for (int i = 0; i < originalText.Length; i = i + 2)
                {
                    if (i + 2 > originalText.Length) {
                        bs[i / 2] = Convert.ToByte(originalText.Substring(i, 1), 16);
                    }
                    else
                    {
                        bs[i / 2] = Convert.ToByte(originalText.Substring(i, 2), 16);
                    }
                }
                richTextBox9.Text = encoding.GetString(bs);
            }
            catch {
                richTextBox9.Text = "转换失败，请输入16进制的字符";
            }



        }

        private void richTextBox18_TextChanged(object sender, EventArgs e)//16进制显示原文长度
        {
            label42.Text = richTextBox18.Text.Length.ToString();
        }

        private void textBox7_Leave(object sender, EventArgs e)
        {
            String originalRGB = textBox7.Text;
            int R = 128;
            int G = 128;
            int B = 128;
            MatchCollection m = Regex.Matches(originalRGB, @"(\d+)");
            int count = -1;
            foreach (Match item in m)
            {
                count++;
                switch (count)
                {
                    case 0: R = Convert.ToInt32(item.Value) % 256; break;
                    case 1: G = Convert.ToInt32(item.Value) % 256; break;
                    case 2: B = Convert.ToInt32(item.Value) % 256; break;
                    default: break;
                }
            }
            textBox7.Text = R + "," + G + "," + B;
            String hex = "#";
            hex += String.Format("{0:X2}", R);
            hex += String.Format("{0:X2}", G);
            hex += String.Format("{0:X2}", B);
            textBox13.Text = hex;
            label34.BackColor = System.Drawing.Color.FromArgb(R,G,B); 
        }

        private void textBox13_Leave(object sender, EventArgs e)
        {
            String originalHex = textBox13.Text;
            int R = 128;
            int G = 128;
            int B = 128;
            MatchCollection m = Regex.Matches(originalHex, @"([0-9a-fA-F]{2})");
            int count = -1;
            foreach (Match item in m)
            {
                count++;
                switch (count)
                {
                    case 0: R = Convert.ToInt32(item.Value,16)%256; break;
                    case 1: G = Convert.ToInt32(item.Value,16)%256; break;
                    case 2: B = Convert.ToInt32(item.Value,16) % 256; break;
                    default: break;
                }
            }
            textBox7.Text = R + "," + G + "," + B;
            String hex = "#";
            hex += String.Format("{0:X2}", R);
            hex += String.Format("{0:X2}", G);
            hex += String.Format("{0:X2}", B);
            textBox13.Text = hex;
            label34.BackColor = System.Drawing.Color.FromArgb(R, G, B);
        }

        private void tabPage4_Click(object sender, EventArgs e)
        {

        }
    }
    static class MyAES
    {
        static PaddingMode[] padding = {
            PaddingMode.PKCS7,
            PaddingMode.ANSIX923,
            PaddingMode.ISO10126,
            PaddingMode.None,
            PaddingMode.Zeros
        };

        static public string Encrypt(string Message, string key, string IV, CipherMode Mode, int pad, int length)
        {
            try
            {
                //RijndaelManaged aes = new RijndaelManaged();
                Rijndael aes = Rijndael.Create();
                //aes.BlockSize = 128;
                //aes.FeedbackSize = 128;
                aes.KeySize = length;
                aes.Padding = padding[pad];
                aes.Mode = Mode;
                //aes.Key = Encoding.UTF8.GetBytes(key);
                //aes.IV = Encoding.UTF8.GetBytes(IV);


                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] keyIV = Encoding.UTF8.GetBytes(IV);
                byte[] inputByteArray = Encoding.UTF8.GetBytes(Message);

                MemoryStream memStream = new MemoryStream();
                CryptoStream crypStream = new CryptoStream(memStream, aes.CreateEncryptor(keyBytes, keyIV), CryptoStreamMode.Write);

                crypStream.Write(inputByteArray, 0, inputByteArray.Length);
                crypStream.FlushFinalBlock();
                aes.Clear();
                return Convert.ToBase64String(memStream.ToArray());
            }
            catch { MessageBox.Show("加密失败"); return ""; }
        }
        //AES加密

        static public string Decrypt(string Ciphertext, string key, string IV, CipherMode Mode, int pad, int length)
        {
            try
            {
                //RijndaelManaged aes = new RijndaelManaged();
                Rijndael aes = Rijndael.Create();
                //aes.BlockSize = 128;
                //aes.FeedbackSize = 128;
                //aes.Key = Encoding.UTF8.GetBytes(key);
                //aes.IV = Encoding.UTF8.GetBytes(IV);
                aes.KeySize = length;
                aes.Padding = padding[pad];
                aes.Mode = Mode;

                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] keyIV = Encoding.UTF8.GetBytes(IV);
                byte[] outputByteArray = Convert.FromBase64String(Ciphertext);

                MemoryStream memStream = new MemoryStream();
                CryptoStream crypStream = new CryptoStream(memStream, aes.CreateDecryptor(keyBytes, keyIV), CryptoStreamMode.Write);
                crypStream.Write(outputByteArray, 0, outputByteArray.Length);
                crypStream.FlushFinalBlock();
                aes.Clear();
                return Encoding.UTF8.GetString(memStream.ToArray());
            }
            catch { MessageBox.Show("加密失败"); return ""; }

        }
        //AES解密




    }
    static class MyDES
    {
        static PaddingMode[] padding = {
            PaddingMode.PKCS7,
            PaddingMode.ANSIX923,
            PaddingMode.ISO10126,
            PaddingMode.None,
            PaddingMode.Zeros
        };
        static public string Encrypt(string Message, string key, string IV, CipherMode Mode, int pad)
        {
            try
            {

                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] keyIV = Encoding.UTF8.GetBytes(IV);
                byte[] inputByteArray = Encoding.UTF8.GetBytes(Message);

                DESCryptoServiceProvider desProvider = new DESCryptoServiceProvider();

                // java 默认的是ECB模式，PKCS5padding；c#默认的CBC模式，PKCS7padding 所以这里我们默认使用ECB方式
                desProvider.Mode = Mode;
                desProvider.Padding = padding[pad];
                MemoryStream memStream = new MemoryStream();
                CryptoStream crypStream = new CryptoStream(memStream, desProvider.CreateEncryptor(keyBytes, keyIV), CryptoStreamMode.Write);

                crypStream.Write(inputByteArray, 0, inputByteArray.Length);
                crypStream.FlushFinalBlock();
                return Convert.ToBase64String(memStream.ToArray());

            }
            catch
            {
                MessageBox.Show("加密失败");
                return "";
            }

        }

        static public string Decrypt(string Message, string key, string IV, CipherMode Mode, int pad)
        {
            try
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] keyIV = Encoding.UTF8.GetBytes(IV);
                byte[] inputByteArray = Convert.FromBase64String(Message);

                DESCryptoServiceProvider desProvider = new DESCryptoServiceProvider();

                // java 默认的是ECB模式，PKCS5padding；c#默认的CBC模式，PKCS7padding 所以这里我们默认使用ECB方式
                desProvider.Mode = Mode;
                desProvider.Padding = padding[pad];
                MemoryStream memStream = new MemoryStream();
                CryptoStream crypStream = new CryptoStream(memStream, desProvider.CreateDecryptor(keyBytes, keyIV), CryptoStreamMode.Write);

                crypStream.Write(inputByteArray, 0, inputByteArray.Length);
                crypStream.FlushFinalBlock();
                return Encoding.Default.GetString(memStream.ToArray());
            }
            catch
            {
                MessageBox.Show("解密失败");
                return "";
            }

        }

    }
    static class MyBase64
    {
        public static Encoding[] encoding = {
                                    Encoding.UTF8,
                                    Encoding.GetEncoding("GB2312"),
                                    Encoding.GetEncoding("GBK"),
                                    Encoding.ASCII,
                                    Encoding.Unicode,
                                    Encoding.UTF7,
                                    Encoding.UTF32,
                                    Encoding.BigEndianUnicode
        };
        static public string EncodeBase64(string Base64_Message, Encoding encoding)
        {
            try
            {
                return System.Convert.ToBase64String(encoding.GetBytes(Base64_Message));
            }
            catch {
                return Base64_Message;
            }
        }


        public static string DecodeBase64(string Base64_Ciphertext, Encoding encoding)
        {
            try
            {
                return encoding.GetString(System.Convert.FromBase64String(Base64_Ciphertext));
            }
            catch
            {
                return Base64_Ciphertext;
            }
        }
    }
    static class MySHA
    {
        public static string[] GetSHAHash(string Message)
        {

            string[] sha = new string[4];
            try
            {
                SHA1 sha1 = new SHA1CryptoServiceProvider();
                SHA256 sha256 = new SHA256CryptoServiceProvider();
                SHA384 sha384 = new SHA384CryptoServiceProvider();
                SHA512 sha512 = new SHA512CryptoServiceProvider();

                byte[] sha_in = UTF8Encoding.Default.GetBytes(Message);

                byte[] sha1_out = sha1.ComputeHash(sha_in);
                byte[] sha256_out = sha256.ComputeHash(sha_in);
                byte[] sha384_out = sha384.ComputeHash(sha_in);
                byte[] sha512_out = sha512.ComputeHash(sha_in);

                sha[0] = BitConverter.ToString(sha1_out).Replace("-", "");
                sha[1] = BitConverter.ToString(sha256_out).Replace("-", "");
                sha[2] = BitConverter.ToString(sha384_out).Replace("-", "");
                sha[3] = BitConverter.ToString(sha512_out).Replace("-", "");
                return sha;
            }
            catch { MessageBox.Show("校验失败"); return sha; }
        }
        public static string[] GetSHAHashFromFile(string fileName)
        {
            string[] sha = new string[4];
            try
            {

                SHA1 sha1 = new SHA1CryptoServiceProvider();
                SHA256 sha256 = new SHA256CryptoServiceProvider();
                SHA384 sha384 = new SHA384CryptoServiceProvider();
                SHA512 sha512 = new SHA512CryptoServiceProvider();

                FileStream file = new FileStream(fileName, FileMode.Open);
                byte[] sha1_out = sha1.ComputeHash(file);
                file.Close();
                file = new FileStream(fileName, FileMode.Open);
                byte[] sha256_out = sha256.ComputeHash(file);
                file.Close();
                file = new FileStream(fileName, FileMode.Open);
                byte[] sha384_out = sha384.ComputeHash(file);
                file.Close();
                file = new FileStream(fileName, FileMode.Open);
                byte[] sha512_out = sha512.ComputeHash(file);
                file.Close();

                sha[0] = BitConverter.ToString(sha1_out).Replace("-", "");
                sha[1] = BitConverter.ToString(sha256_out).Replace("-", "");
                sha[2] = BitConverter.ToString(sha384_out).Replace("-", "");
                sha[3] = BitConverter.ToString(sha512_out).Replace("-", "");
                return sha;

            }
            catch
            { MessageBox.Show("校验失败"); return sha; }

        }

    }
    static class MyMD5
    {
        public static string GetMD5Hash(string Message, bool MD5_Mode)
        {
            try
            {
                byte[] result = Encoding.Default.GetBytes(Message);
                MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
                byte[] output = md5.ComputeHash(result);
                if (MD5_Mode == true) return BitConverter.ToString(output).Replace("-", "");//32位MD5值
                else return BitConverter.ToString(output, 4, 8).Replace("-", "");           //16位MD5值
            }
            catch { MessageBox.Show("校验失败"); return ""; }

        }
        public static string GetMD5HashFromFile(string fileName, bool MD5_Mode)
        {
            try
            {
                FileStream file = new FileStream(fileName, FileMode.Open);
                System.Security.Cryptography.MD5 md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
                byte[] retVal = md5.ComputeHash(file);
                file.Close();

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < retVal.Length; i++)
                {
                    sb.Append(retVal[i].ToString("x2"));
                }
                if (MD5_Mode == true) return sb.ToString().ToUpper();
                else return sb.ToString().Substring(8, 16).ToUpper();

            }
            catch { MessageBox.Show("校验失败"); return ""; }
        }
    }
    static class MyUrl
    {
        public static string Encode(string plain,Encoding encoding)//部分编码
        {
            return HttpUtility.UrlEncode(plain,encoding);
        }

        public static string Decode(string text, Encoding encoding)//解码
        {
            return HttpUtility.UrlDecode(text, encoding);
        }
    }
    static class MyHtml {
        public static string Encode(string plain,bool flag) {
            string r = string.Empty;
            if (flag)//10进制
            {
                for (int i = 0; i < plain.Length; i++)
                {
                    r += "&#" + Char.ConvertToUtf32(plain, i) + ";";
                }
            }
            else {
                //16进制
                for (int i = 0; i < plain.Length; i++)
                {
                    r += "&#x" + Char.ConvertToUtf32(plain, i).ToString("x4") + ";";
                }
            }
            return r;
            
        }
        public static string Decode(string text)
        {
            string t = string.Empty;
            Regex regex1 = new Regex(@"&#x([0-9,a-f,A-F]+);");
            Regex regex2 = new Regex(@"&#([0-9]+);");

            while (regex1.IsMatch(text)) {  //解码16进制的html实体编码
                t = regex1.Match(text).Groups[1].Value;
                text = regex1.Replace(text,Char.ConvertFromUtf32(Convert.ToInt32(t, 16)),1);  
            }
            while (regex2.IsMatch(text))    //解码10进制的html实体编码
            {
                t = regex2.Match(text).Groups[1].Value;
                text = regex2.Replace(text, Char.ConvertFromUtf32(Convert.ToInt32(t, 10)), 1);
            }
            return text;
        }
    }
}
