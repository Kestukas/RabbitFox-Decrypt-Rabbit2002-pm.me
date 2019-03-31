using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using IniParser;
using IniParser.Model;


namespace FoxCryptoDecrypt
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            var parser = new FileIniDataParser();
            IniData data = parser.ReadFile("Configuration.ini");
            textBox1.Text = data["VirusExt"]["value"];


        }

        private void button1_Click(object sender, EventArgs e)
        {
            GetAllSignatures();
        }


        Dictionary<string, string> Byte1g = new Dictionary<string, string>();
        Dictionary<string, string> Byte2g = new Dictionary<string, string>();
        Dictionary<string, string> Byte3g = new Dictionary<string, string>();
        Dictionary<string, string> Byte4g = new Dictionary<string, string>();
        Dictionary<string, string> Byte5g = new Dictionary<string, string>();
        Dictionary<string, string> Byte6g = new Dictionary<string, string>();
        Dictionary<string, string> Byte7g = new Dictionary<string, string>();
        Dictionary<string, string> Byte8g = new Dictionary<string, string>();
        Dictionary<string, string> Byte9g = new Dictionary<string, string>();
        Dictionary<string, string> Byte10g = new Dictionary<string, string>();

        Dictionary<string, string> Byte1b = new Dictionary<string, string>();
        Dictionary<string, string> Byte2b = new Dictionary<string, string>();
        Dictionary<string, string> Byte3b = new Dictionary<string, string>();
        Dictionary<string, string> Byte4b = new Dictionary<string, string>();
        Dictionary<string, string> Byte5b = new Dictionary<string, string>();
        Dictionary<string, string> Byte6b = new Dictionary<string, string>();
        Dictionary<string, string> Byte7b = new Dictionary<string, string>();
        Dictionary<string, string> Byte8b = new Dictionary<string, string>();
        Dictionary<string, string> Byte9b = new Dictionary<string, string>();
        Dictionary<string, string> Byte10b = new Dictionary<string, string>();

        Dictionary<string, Dictionary<string, string>> AllVars = new Dictionary<string, Dictionary<string, string>>();



        private void GetAllSignatures()
        {
            var parser = new FileIniDataParser();
            IniData SigLines = parser.ReadFile("Configuration.ini");


            Dictionary<string, string> Signatures = new Dictionary<string, string>();
            Dictionary<string, string> UniqueFiles = new Dictionary<string, string>();



            KeyDataCollection Extentions = SigLines["Ext"];

            foreach (KeyData line in Extentions)
            {

                Signatures.Add(line.KeyName, line.Value);

            }


            var parser2 = new FileIniDataParser();
            IniData UniqueLines = parser2.ReadFile("UniqueFiles.ini");

            KeyDataCollection Files2 = UniqueLines["Filename"];

            foreach (KeyData line in Files2)
            {

                UniqueFiles.Add(line.KeyName, line.Value);

            }


            string[] allFiles = Directory.GetFiles(textBox3.Text, "*.*" + textBox1.Text, SearchOption.AllDirectories);







            foreach (string file in allFiles)
            {

                if (file.ToLower().Contains("decrypt.txt")) { File.Delete(file); }

                string OriginalFile = file.Replace(textBox1.Text, "").Trim();


                if (OriginalFile.Contains(".") && file.Contains(textBox1.Text))
                {
                    string extention = OriginalFile.Remove(0, OriginalFile.LastIndexOf(".") + 1);

                    if (Signatures.ContainsKey(extention.ToLower()) && !File.Exists(OriginalFile))
                    {
                        FileStream fs = File.OpenRead(file);
                        byte[] data = StringToByteArray(Signatures[extention.ToLower()]);


                        byte[] buffer;
                        BinaryReader bReaderImg = new BinaryReader(fs);
                        buffer = bReaderImg.ReadBytes(Convert.ToInt32(fs.Length));
                        FileStream file1 = new FileStream(OriginalFile, FileMode.Create, FileAccess.Write);
                        BinaryWriter bWriterImg = new BinaryWriter(file1);

                        string PureFileName = OriginalFile.Remove(0, OriginalFile.LastIndexOf("\\") + 1).ToLower();

                        if (UniqueFiles.ContainsKey(PureFileName))
                        {
                            data = StringToByteArray(UniqueFiles[PureFileName]);


                            data[5] = buffer[25];
                            data[6] = buffer[26];


                        }


                        if (extention.ToLower() == "dat") { data[5] = buffer[25]; data[6] = buffer[26]; }

                        buffer[0] = data[0];
                        buffer[1] = data[1];
                        buffer[2] = data[2];
                        buffer[3] = data[3];
                        buffer[4] = data[4];
                        buffer[5] = data[5];
                        buffer[6] = data[6];
                        buffer[7] = data[7];
                        buffer[8] = data[8];
                        buffer[9] = data[9];


                        bWriterImg.Write(buffer);
                        bWriterImg.BaseStream.Position = (0x00000);
                        bWriterImg.Write(data);


                        fs.Close();
                        file1.Close();

                        File.Delete(file);
                    }







                }




            }


        }

        private void button2_Click(object sender, EventArgs e)
        {
            DialogResult result = folderBrowserDialog1.ShowDialog();

            if (result == DialogResult.OK && !string.IsNullOrWhiteSpace(folderBrowserDialog1.SelectedPath))
            {
                textBox3.Text = folderBrowserDialog1.SelectedPath;
            }

        }




        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }


        public static void CopyStream(Stream input, Stream output)
        {
            byte[] buffer = new byte[8 * 1024];
            int len;
            while ((len = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, len);
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {

            string[] allFiles = Directory.GetFiles(textBox3.Text, "*.*", SearchOption.AllDirectories);

            var parser = new FileIniDataParser();
            IniData data = new IniData();




            foreach (string file in allFiles)
            {

                try
                {
                    FileStream fs = File.OpenRead(file);



                    byte[] buffer;
                    BinaryReader bReaderImg = new BinaryReader(fs);
                    buffer = bReaderImg.ReadBytes(Convert.ToInt32(fs.Length));

                    byte[] hexdata = { buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9] };
                    string hex = BitConverter.ToString(hexdata);



                    data["Filename"][file] = hex;



                }
                catch { }

            }

            parser.WriteFile("UniqueFiles.ini", data);

        }


        private void doNewList()
        {
            AllVars.Add("BYTE01", new Dictionary<string, string>());
            AllVars.Add("BYTE02", new Dictionary<string, string>());
            AllVars.Add("BYTE03", new Dictionary<string, string>());
            AllVars.Add("BYTE04", new Dictionary<string, string>());
            AllVars.Add("BYTE05", new Dictionary<string, string>());
            AllVars.Add("BYTE06", new Dictionary<string, string>());
            AllVars.Add("BYTE07", new Dictionary<string, string>());
            AllVars.Add("BYTE08", new Dictionary<string, string>());
            AllVars.Add("BYTE09", new Dictionary<string, string>());
            AllVars.Add("BYTE10", new Dictionary<string, string>());


            string[] allFiles = Directory.GetFiles(textBox3.Text, "*.*", SearchOption.AllDirectories);

            var parser = new FileIniDataParser();
            IniData data = new IniData();



            //foreach good files
            foreach (string file in allFiles)
            {


                try
                {

                    if (!file.Contains("Rabbit2002@pm.me"))
                    {
                    FileStream fs = File.OpenRead(file);
                    byte[] buffer;
                    BinaryReader bReaderImg = new BinaryReader(fs);
                    buffer = bReaderImg.ReadBytes(Convert.ToInt32(fs.Length));

                    byte[] hexdata = { buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9] };
                    string hex = BitConverter.ToString(hexdata);


                        // if good file :
                        string FileSig = file.Replace(textBox3.Text, "").Replace("\\Geri\\", "").Replace("\\Blogi\\", "") + "_"+ buffer.Length;


                        if (!Byte1g.ContainsKey(FileSig)) { Byte1g.Add(FileSig,BitConverter.ToString(new byte[] { buffer[0] })); }
                        if (!Byte2g.ContainsKey(FileSig)) { Byte2g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[1] })); }
                        if (!Byte3g.ContainsKey(FileSig)) { Byte3g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[2] })); }
                        if (!Byte4g.ContainsKey(FileSig)) { Byte4g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[3] })); }
                        if (!Byte5g.ContainsKey(FileSig)) { Byte5g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[4] })); }
                        if (!Byte6g.ContainsKey(FileSig)) { Byte6g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[5] })); }
                        if (!Byte7g.ContainsKey(FileSig)) { Byte7g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[6] })); }
                        if (!Byte8g.ContainsKey(FileSig)) { Byte8g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[7] })); }
                        if (!Byte9g.ContainsKey(FileSig)) { Byte9g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[8] })); }
                        if (!Byte10g.ContainsKey(FileSig)) { Byte10g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[9] })); }

                    }
                    

                }
                catch { }

            }
            //foreach BAD files
            foreach (string file in allFiles)
            {


                try
                { // if good file :
                    if (file.Contains("Rabbit2002@pm.me"))
                    {
                    FileStream fs = File.OpenRead(file);
                    byte[] buffer;
                    BinaryReader bReaderImg = new BinaryReader(fs);
                    buffer = bReaderImg.ReadBytes(Convert.ToInt32(fs.Length));

                    byte[] hexdata = { buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9] };
                    string hex = BitConverter.ToString(hexdata);


                        string FileSig = file.Replace(textBox3.Text, "").Replace("\\Geri\\", "").Replace("\\Blogi\\", "").Replace(" id 1720406111[Rabbit2002@pm.me].fox", "") + "_" + buffer.Length; ;



                        if (!Byte1b.ContainsKey(FileSig) && IsGood(Byte1g, buffer[0], FileSig)) { Byte1b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[0] })); } 
                        if (!Byte2b.ContainsKey(FileSig) && IsGood(Byte2g, buffer[1], FileSig)) { Byte2b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[1] })); }
                        if (!Byte3b.ContainsKey(FileSig) && IsGood(Byte3g, buffer[2], FileSig)) { Byte3b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[2] })); }
                        if (!Byte4b.ContainsKey(FileSig) && IsGood(Byte4g, buffer[3], FileSig)) { Byte4b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[3] })); }
                        if (!Byte5b.ContainsKey(FileSig) && IsGood(Byte5g, buffer[4], FileSig)) { Byte5b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[4] })); }
                        if (!Byte6b.ContainsKey(FileSig) && IsGood(Byte6g, buffer[5], FileSig)) { Byte6b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[5] })); }
                        if (!Byte7b.ContainsKey(FileSig) && IsGood(Byte7g, buffer[6], FileSig)) { Byte7b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[6] })); }
                        if (!Byte8b.ContainsKey(FileSig) && IsGood(Byte8g, buffer[7], FileSig)) { Byte8b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[7] })); }
                        if (!Byte9b.ContainsKey(FileSig) && IsGood(Byte9g, buffer[8], FileSig)) { Byte9b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[8] })); }
                        if (!Byte10b.ContainsKey(FileSig) && IsGood(Byte10g, buffer[9], FileSig)) { Byte10b.Add(FileSig,BitConverter.ToString(new byte[] { buffer[9] })); }

                    }


                }
                catch { }

            }

            


            /// darom ini
            /// 1
            foreach (var Byte in Byte1b)
            {   if (Byte1g.ContainsKey(Byte.Key))
                { data["BYTE01"][Byte.Value] = Byte1g[Byte.Key]; if (!AllVars["BYTE01"].ContainsKey(Byte.Value))  { AllVars["BYTE01"].Add(Byte.Value, Byte1g[Byte.Key]); } }
            }

            /// 2
            foreach (var Byte in Byte2b)
            {
                if (Byte2g.ContainsKey(Byte.Key))
                { data["BYTE02"][Byte.Value] = Byte2g[Byte.Key]; if (!AllVars["BYTE02"].ContainsKey(Byte.Value)) { AllVars["BYTE02"].Add(Byte.Value, Byte2g[Byte.Key]); } }
            }
            /// 3
            foreach (var Byte in Byte3b)
            {
                if (Byte3g.ContainsKey(Byte.Key))
                { data["BYTE03"][Byte.Value] = Byte3g[Byte.Key]; if (!AllVars["BYTE03"].ContainsKey(Byte.Value)) { AllVars["BYTE03"].Add(Byte.Value, Byte3g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte4b)
            {
                if (Byte4g.ContainsKey(Byte.Key))
                { data["BYTE04"][Byte.Value] = Byte4g[Byte.Key]; if (!AllVars["BYTE04"].ContainsKey(Byte.Value)) { AllVars["BYTE04"].Add(Byte.Value, Byte4g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte5b)
            {
                if (Byte5g.ContainsKey(Byte.Key))
                { data["BYTE05"][Byte.Value] = Byte5g[Byte.Key]; if (!AllVars["BYTE05"].ContainsKey(Byte.Value)) { AllVars["BYTE05"].Add(Byte.Value, Byte5g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte6b)
            {
                if (Byte6g.ContainsKey(Byte.Key))
                { data["BYTE06"][Byte.Value] = Byte6g[Byte.Key]; if (!AllVars["BYTE06"].ContainsKey(Byte.Value)) { AllVars["BYTE06"].Add(Byte.Value, Byte6g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte7b)
            {
                if (Byte7g.ContainsKey(Byte.Key))
                { data["BYTE07"][Byte.Value] = Byte7g[Byte.Key]; if (!AllVars["BYTE07"].ContainsKey(Byte.Value)) { AllVars["BYTE07"].Add(Byte.Value, Byte7g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte8b)
            {
                if (Byte8g.ContainsKey(Byte.Key))
                { data["BYTE08"][Byte.Value] = Byte8g[Byte.Key]; if (!AllVars["BYTE08"].ContainsKey(Byte.Value)) { AllVars["BYTE08"].Add(Byte.Value, Byte8g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte9b)
            {
                if (Byte9g.ContainsKey(Byte.Key))
                { data["BYTE09"][Byte.Value] = Byte9g[Byte.Key]; if (!AllVars["BYTE09"].ContainsKey(Byte.Value)) { AllVars["BYTE09"].Add(Byte.Value, Byte9g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte10b)
            {
                if (Byte10g.ContainsKey(Byte.Key))
                { data["BYTE10"][Byte.Value] = Byte10g[Byte.Key]; if (!AllVars["BYTE10"].ContainsKey(Byte.Value)) { AllVars["BYTE10"].Add(Byte.Value, Byte10g[Byte.Key]); } }
            }


            parser.WriteFile("HEX.ini", data);

            string AllVarsText = "";
            foreach (KeyValuePair<string,Dictionary<string,string>> BYTE in AllVars)
            {

                foreach(var dic3 in BYTE.Value)
                {
                    AllVarsText = AllVarsText + BYTE.Key + ";" + dic3.Key + ";" + dic3.Value + "\r\n"; 
                    
                }
                
            }


            File.WriteAllText("AllVars.csv", AllVarsText);





            MessageBox.Show("written hex.ini");

        }


        private void doNewList2()
        {
            AllVars.Add("BYTE01", new Dictionary<string, string>());
            AllVars.Add("BYTE02", new Dictionary<string, string>());
            AllVars.Add("BYTE03", new Dictionary<string, string>());
            AllVars.Add("BYTE04", new Dictionary<string, string>());
            AllVars.Add("BYTE05", new Dictionary<string, string>());
            AllVars.Add("BYTE06", new Dictionary<string, string>());
            AllVars.Add("BYTE07", new Dictionary<string, string>());
            AllVars.Add("BYTE08", new Dictionary<string, string>());
            AllVars.Add("BYTE09", new Dictionary<string, string>());
            AllVars.Add("BYTE10", new Dictionary<string, string>());


            string[] allFiles = Directory.GetFiles(textBox3.Text, "*.*", SearchOption.AllDirectories);

            var parser = new FileIniDataParser();
            IniData data = new IniData();



            //foreach good files
            foreach (string file in allFiles)
            {


                try
                {

                    if (!file.Contains("Rabbit2002@pm.me"))
                    {
                        FileStream fs = File.OpenRead(file);
                        byte[] buffer;
                        BinaryReader bReaderImg = new BinaryReader(fs);
                        buffer = bReaderImg.ReadBytes(Convert.ToInt32(fs.Length));

                        byte[] hexdata = { buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9] };
                        string hex = BitConverter.ToString(hexdata);


                        // if good file :
                        string PureFileName = file.Remove(0, file.LastIndexOf("\\") + 1).ToLower();



                        string FileSig = PureFileName.Replace(textBox3.Text, "").Replace("\\Geri\\", "").Replace("\\Blogi\\", "") + "_" + buffer.Length;


                        if (!Byte1g.ContainsKey(FileSig)) { Byte1g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[0] })); }
                        if (!Byte2g.ContainsKey(FileSig)) { Byte2g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[1] })); }
                        if (!Byte3g.ContainsKey(FileSig)) { Byte3g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[2] })); }
                        if (!Byte4g.ContainsKey(FileSig)) { Byte4g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[3] })); }
                        if (!Byte5g.ContainsKey(FileSig)) { Byte5g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[4] })); }
                        if (!Byte6g.ContainsKey(FileSig)) { Byte6g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[5] })); }
                        if (!Byte7g.ContainsKey(FileSig)) { Byte7g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[6] })); }
                        if (!Byte8g.ContainsKey(FileSig)) { Byte8g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[7] })); }
                        if (!Byte9g.ContainsKey(FileSig)) { Byte9g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[8] })); }
                        if (!Byte10g.ContainsKey(FileSig)) { Byte10g.Add(FileSig, BitConverter.ToString(new byte[] { buffer[9] })); }

                    }


                }
                catch { }

            }
            //foreach BAD files
            foreach (string file in allFiles)
            {


                try
                { // if good file :
                    if (file.Contains("Rabbit2002@pm.me"))
                    {
                        FileStream fs = File.OpenRead(file);
                        byte[] buffer;
                        BinaryReader bReaderImg = new BinaryReader(fs);
                        buffer = bReaderImg.ReadBytes(Convert.ToInt32(fs.Length));

                        byte[] hexdata = { buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9] };
                        string hex = BitConverter.ToString(hexdata);
                        string PureFileName = file.Remove(0, file.LastIndexOf("\\") + 1).ToLower();


                        string FileSig = PureFileName.Replace(textBox3.Text, "").Replace("\\Geri\\", "").Replace("\\Blogi\\", "").Replace(" id 1720406111[Rabbit2002@pm.me].fox", "") + "_" + buffer.Length; ;



                        if (!Byte1b.ContainsKey(FileSig) && IsGood(Byte1g, buffer[0], FileSig)) { Byte1b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[0] })); }
                        if (!Byte2b.ContainsKey(FileSig) && IsGood(Byte2g, buffer[1], FileSig)) { Byte2b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[1] })); }
                        if (!Byte3b.ContainsKey(FileSig) && IsGood(Byte3g, buffer[2], FileSig)) { Byte3b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[2] })); }
                        if (!Byte4b.ContainsKey(FileSig) && IsGood(Byte4g, buffer[3], FileSig)) { Byte4b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[3] })); }
                        if (!Byte5b.ContainsKey(FileSig) && IsGood(Byte5g, buffer[4], FileSig)) { Byte5b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[4] })); }
                        if (!Byte6b.ContainsKey(FileSig) && IsGood(Byte6g, buffer[5], FileSig)) { Byte6b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[5] })); }
                        if (!Byte7b.ContainsKey(FileSig) && IsGood(Byte7g, buffer[6], FileSig)) { Byte7b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[6] })); }
                        if (!Byte8b.ContainsKey(FileSig) && IsGood(Byte8g, buffer[7], FileSig)) { Byte8b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[7] })); }
                        if (!Byte9b.ContainsKey(FileSig) && IsGood(Byte9g, buffer[8], FileSig)) { Byte9b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[8] })); }
                        if (!Byte10b.ContainsKey(FileSig) && IsGood(Byte10g, buffer[9], FileSig)) { Byte10b.Add(FileSig, BitConverter.ToString(new byte[] { buffer[9] })); }

                    }


                }
                catch { }

            }




            /// darom ini
            /// 1
            foreach (var Byte in Byte1b)
            {
                if (Byte1g.ContainsKey(Byte.Key))
                { data["BYTE01"][Byte.Value] = Byte1g[Byte.Key]; if (!AllVars["BYTE01"].ContainsKey(Byte.Value)) { AllVars["BYTE01"].Add(Byte.Value, Byte1g[Byte.Key]); } }
            }

            /// 2
            foreach (var Byte in Byte2b)
            {
                if (Byte2g.ContainsKey(Byte.Key))
                { data["BYTE02"][Byte.Value] = Byte2g[Byte.Key]; if (!AllVars["BYTE02"].ContainsKey(Byte.Value)) { AllVars["BYTE02"].Add(Byte.Value, Byte2g[Byte.Key]); } }
            }
            /// 3
            foreach (var Byte in Byte3b)
            {
                if (Byte3g.ContainsKey(Byte.Key))
                { data["BYTE03"][Byte.Value] = Byte3g[Byte.Key]; if (!AllVars["BYTE03"].ContainsKey(Byte.Value)) { AllVars["BYTE03"].Add(Byte.Value, Byte3g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte4b)
            {
                if (Byte4g.ContainsKey(Byte.Key))
                { data["BYTE04"][Byte.Value] = Byte4g[Byte.Key]; if (!AllVars["BYTE04"].ContainsKey(Byte.Value)) { AllVars["BYTE04"].Add(Byte.Value, Byte4g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte5b)
            {
                if (Byte5g.ContainsKey(Byte.Key))
                { data["BYTE05"][Byte.Value] = Byte5g[Byte.Key]; if (!AllVars["BYTE05"].ContainsKey(Byte.Value)) { AllVars["BYTE05"].Add(Byte.Value, Byte5g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte6b)
            {
                if (Byte6g.ContainsKey(Byte.Key))
                { data["BYTE06"][Byte.Value] = Byte6g[Byte.Key]; if (!AllVars["BYTE06"].ContainsKey(Byte.Value)) { AllVars["BYTE06"].Add(Byte.Value, Byte6g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte7b)
            {
                if (Byte7g.ContainsKey(Byte.Key))
                { data["BYTE07"][Byte.Value] = Byte7g[Byte.Key]; if (!AllVars["BYTE07"].ContainsKey(Byte.Value)) { AllVars["BYTE07"].Add(Byte.Value, Byte7g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte8b)
            {
                if (Byte8g.ContainsKey(Byte.Key))
                { data["BYTE08"][Byte.Value] = Byte8g[Byte.Key]; if (!AllVars["BYTE08"].ContainsKey(Byte.Value)) { AllVars["BYTE08"].Add(Byte.Value, Byte8g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte9b)
            {
                if (Byte9g.ContainsKey(Byte.Key))
                { data["BYTE09"][Byte.Value] = Byte9g[Byte.Key]; if (!AllVars["BYTE09"].ContainsKey(Byte.Value)) { AllVars["BYTE09"].Add(Byte.Value, Byte9g[Byte.Key]); } }
            }
            /// 1
            foreach (var Byte in Byte10b)
            {
                if (Byte10g.ContainsKey(Byte.Key))
                { data["BYTE10"][Byte.Value] = Byte10g[Byte.Key]; if (!AllVars["BYTE10"].ContainsKey(Byte.Value)) { AllVars["BYTE10"].Add(Byte.Value, Byte10g[Byte.Key]); } }
            }


            parser.WriteFile("HEX.ini", data);

            string AllVarsText = "";
            foreach (KeyValuePair<string, Dictionary<string, string>> BYTE in AllVars)
            {

                foreach (var dic3 in BYTE.Value)
                {
                    AllVarsText = AllVarsText + BYTE.Key + ";" + dic3.Key + ";" + dic3.Value + "\r\n";

                }

            }


            File.WriteAllText("AllVars.csv", AllVarsText);





            MessageBox.Show("written hex.ini");

        }

        private bool IsGood(Dictionary<string,string> dic,byte byte1,string FileSig)
        {
            bool answer = true;

            if (dic.ContainsKey(FileSig))
            {
                if (dic[FileSig] == BitConverter.ToString(new byte[] { byte1 })) { answer = false;  }

            }





            return answer;
        }


        private void button4_Click(object sender, EventArgs e)
        {

            string[] allFiles = Directory.GetFiles(textBox3.Text, "*.dat", SearchOption.AllDirectories);

            var parser = new FileIniDataParser();
            IniData data = new IniData();

            int i = 0;


            foreach (string file in allFiles)
            {
                i++;
                try
                {
                    FileStream fs = File.OpenRead(file);



                    byte[] buffer;
                    BinaryReader bReaderImg = new BinaryReader(fs);
                    buffer = bReaderImg.ReadBytes(Convert.ToInt32(fs.Length));

                    byte[] hexdata = { buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19], buffer[20], buffer[21], buffer[22], buffer[23], buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30], buffer[31], buffer[32], buffer[33], buffer[34], buffer[35], buffer[36], buffer[37], buffer[38], buffer[39] };
                    string hex = BitConverter.ToString(hexdata);

                    File.AppendAllText("sigs.txt", file.ToLower().Remove(0, file.LastIndexOf("\\") + 1) + "-" + hex+"\r\n");


                    data["HEX"][file.ToLower().Remove(0, file.LastIndexOf("\\") + 1)] = hex;



                }
                catch { }

            }

            parser.WriteFile("UniqueFiles2.ini", data);
        }

        private void button5_Click(object sender, EventArgs e)
        {
            doNewList();
        }

        private void button6_Click(object sender, EventArgs e)
        {
            DecryptUsingHex();

            MessageBox.Show("done");
        }








        private void DecryptUsingHex()
        {

            Dictionary<string, string> DoneByte1 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte2 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte3 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte4 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte5 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte6 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte7 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte8 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte9 = new Dictionary<string, string>();
            Dictionary<string, string> DoneByte10 = new Dictionary<string, string>();



            var parser = new FileIniDataParser();
            IniData SigLines = parser.ReadFile("Configuration.ini");


            IniData HexLines = parser.ReadFile("hex.ini");



            Dictionary<string, string> Signatures = new Dictionary<string, string>();
            Dictionary<string, string> UniqueFiles = new Dictionary<string, string>();


            KeyDataCollection Bytes1 = HexLines["BYTE01"]; foreach (KeyData line in Bytes1) { DoneByte1.Add(line.KeyName, line.Value); }
           
            Bytes1 = HexLines["BYTE02"]; foreach (KeyData line in Bytes1) { DoneByte2.Add(line.KeyName, line.Value); }
            Bytes1 = HexLines["BYTE03"]; foreach (KeyData line in Bytes1) { DoneByte3.Add(line.KeyName, line.Value); }
            Bytes1 = HexLines["BYTE04"]; foreach (KeyData line in Bytes1) { DoneByte4.Add(line.KeyName, line.Value); }
            Bytes1 = HexLines["BYTE05"]; foreach (KeyData line in Bytes1) { DoneByte5.Add(line.KeyName, line.Value); }
            Bytes1 = HexLines["BYTE06"]; foreach (KeyData line in Bytes1) { DoneByte6.Add(line.KeyName, line.Value); }
            Bytes1 = HexLines["BYTE07"]; foreach (KeyData line in Bytes1) { DoneByte7.Add(line.KeyName, line.Value); }
            Bytes1 = HexLines["BYTE08"]; foreach (KeyData line in Bytes1) { DoneByte8.Add(line.KeyName, line.Value); }
            Bytes1 = HexLines["BYTE09"]; foreach (KeyData line in Bytes1) { DoneByte9.Add(line.KeyName, line.Value); }
            Bytes1 = HexLines["BYTE10"]; foreach (KeyData line in Bytes1) { DoneByte10.Add(line.KeyName, line.Value); }

            KeyDataCollection Extentions = SigLines["Ext"];

            foreach (KeyData line in Extentions)
            {

                Signatures.Add(line.KeyName, line.Value);

            }


            var parser2 = new FileIniDataParser();
            IniData UniqueLines = parser2.ReadFile("UniqueFiles.ini");

            KeyDataCollection Files2 = UniqueLines["Filename"];

            foreach (KeyData line in Files2)
            {

                UniqueFiles.Add(line.KeyName, line.Value);

            }

            string[] allFiles = Directory.GetFiles(textBox3.Text, "*.*" + textBox1.Text, SearchOption.AllDirectories);

            

            foreach (string file in allFiles)
            {

                if (file.ToLower().Contains("decrypt.txt")) { File.Delete(file); }


                string OriginalFile = file.Replace(textBox1.Text, "").Trim();


                if (OriginalFile.Contains(".") && file.Contains(textBox1.Text))
                {
                    string extention = OriginalFile.Remove(0, OriginalFile.LastIndexOf(".") + 1);

                    FileStream fs = File.OpenRead(file);
                    byte[] buffer;
                    BinaryReader bReaderImg = new BinaryReader(fs);
                    buffer = bReaderImg.ReadBytes(Convert.ToInt32(fs.Length));

                    byte[] hexdata = { buffer[0] };


                    if (buffer.Length > 10)
                    {
                        hexdata = new byte[] { buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9], buffer[10]};
                    }

                    if (buffer.Length > 40)
                    {
                        hexdata = new byte [] { buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19], buffer[20], buffer[21], buffer[22], buffer[23], buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30], buffer[31], buffer[32], buffer[33], buffer[34], buffer[35], buffer[36], buffer[37], buffer[38], buffer[39] };
                    }


                    string Hex01 = BitConverter.ToString(new byte[] { buffer[0] });
                    string Hex02 = BitConverter.ToString(new byte[] { buffer[1] });
                    string Hex03 = BitConverter.ToString(new byte[] { buffer[2] });
                    string Hex04 = BitConverter.ToString(new byte[] { buffer[3] });
                    string Hex05 = BitConverter.ToString(new byte[] { buffer[4] });
                    string Hex06 = BitConverter.ToString(new byte[] { buffer[5] });
                    string Hex07 = BitConverter.ToString(new byte[] { buffer[6] });
                    string Hex08 = BitConverter.ToString(new byte[] { buffer[7] });
                    string Hex09 = BitConverter.ToString(new byte[] { buffer[8] });
                    string Hex10 = BitConverter.ToString(new byte[] { buffer[9] });







                    string hex = BitConverter.ToString(hexdata);


                    



                    byte[] data = StringToByteArray("ffffffffffffffffffff");

                    if (Signatures.ContainsKey(extention.ToLower())) { data = StringToByteArray(Signatures[extention.ToLower()]); }
                    else
                    {
                        data = buffer;
                    }


                        
                      
                        FileStream file1 = new FileStream(OriginalFile, FileMode.Create, FileAccess.Write);
                        BinaryWriter bWriterImg = new BinaryWriter(file1);

                        string PureFileName = OriginalFile.Remove(0, OriginalFile.LastIndexOf("\\") + 1).ToLower();

                        if (UniqueFiles.ContainsKey(PureFileName))
                        {
                            data = StringToByteArray(UniqueFiles[PureFileName]);


                            data[5] = buffer[25];
                            data[6] = buffer[26];


                        }


                    
                        buffer[0] = data[0];
                        buffer[1] = data[1];
                        buffer[2] = data[2];
                        buffer[3] = data[3];
                        buffer[4] = data[4];
                        buffer[5] = data[5];
                        buffer[6] = data[6];
                        buffer[7] = data[7];
                        buffer[8] = data[8];
                        buffer[9] = data[9];

                    if (extention.ToLower() == "dat") { buffer[5] = buffer[25]; buffer[6] = buffer[26]; }


                    /// dedam compare

                    if (DoneByte1.ContainsKey(Hex01)) { buffer[0] = StringToByteArray(DoneByte1[Hex01])[0]; }
                    if (DoneByte2.ContainsKey(Hex02)) { buffer[1] = StringToByteArray(DoneByte2[Hex02])[0]; }
                    if (DoneByte3.ContainsKey(Hex03)) { buffer[2] = StringToByteArray(DoneByte3[Hex03])[0]; }
                    if (DoneByte4.ContainsKey(Hex04)) { buffer[3] = StringToByteArray(DoneByte4[Hex04])[0]; }
                    if (DoneByte5.ContainsKey(Hex05)) { buffer[4] = StringToByteArray(DoneByte5[Hex05])[0]; }
                    if (DoneByte6.ContainsKey(Hex06)) { buffer[5] = StringToByteArray(DoneByte6[Hex06])[0]; }
                    if (DoneByte7.ContainsKey(Hex07)) { buffer[6] = StringToByteArray(DoneByte7[Hex07])[0]; }
                    if (DoneByte8.ContainsKey(Hex08)) { buffer[7] = StringToByteArray(DoneByte8[Hex08])[0]; }
                    if (DoneByte9.ContainsKey(Hex09)) { buffer[8] = StringToByteArray(DoneByte9[Hex09])[0]; }
                    if (DoneByte10.ContainsKey(Hex10)) { buffer[9] = StringToByteArray(DoneByte10[Hex10])[0]; }



                   






                    bWriterImg.Write(buffer);
                        bWriterImg.BaseStream.Position = (0x00000);
                        bWriterImg.Write(data);


                        fs.Close();
                        file1.Close();

                        File.Delete(file);
                    







                }




            }


        }

        private void button7_Click(object sender, EventArgs e)
        {
            doNewList2();
        }
    }



}
