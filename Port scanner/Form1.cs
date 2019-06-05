//    Copyright(C) 2019  KuzyXD

//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.

//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//    GNU General Public License for more details.

//    You should have received a copy of the GNU General Public License
//    along with this program.If not, see<https://www.gnu.org/licenses/>.
//
//Contacts: email: kuzyxd@yandex.ru \ Discord: KuzyXD#2772 \ VK: vk.com/kuzyxd

using System;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using CsQuery;

namespace Port_scanner
{
    public partial class Form1 : Form
    {
        private string ipStart;
        private string ipEnd;
        private int portStart;
        private int portEnd;
        private int numThread = 100;
        private int overTime = 20;
        private Thread t;
        private Thread scanthread;
        private bool[] done = new bool[65536];  
        private bool ok;
        private int port;
        private CQ htmllink = CQ.CreateFromUrl("http://lists.thedatalist.com/portlist/portlist.php");
        List<string> str;

        public Form1()
        {
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;
        }

        private void Form1_Load(object sender, EventArgs e)
        {

            if (textBox1.Text!= "")
            {
                ipStart = textBox1.Text;
            }
            if(textBox3.Text!="")
            {
                portStart = int.Parse(textBox3.Text);
            }

            if (checkBox2.Checked)
            {
                textBox1.ReadOnly = true;
            }

            if (checkBox3.Checked)
            {
                textBox4.ReadOnly = true;
            }

            overTime = 20;

            listBox1.Items.Add("IP-адрес              " + "    Порт       " + "  Статус порта " + "             Сервис");
        }

        private void textBox4_TextChanged(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            button2.Enabled = true;

            listBox1.Items.Clear();
            if(str != null)
            {
                str.RemoveRange(0, str.Count);
            }
            
            listBox1.Items.Add("IP-адрес              " + "    Порт       " + "  Статус порта " + "             Сервис");
        

          if(checkBox2.Checked)
          {
              textBox2.Text = textBox1.Text;
          }
          if (checkBox3.Checked)
          {
              textBox4.Text = textBox3.Text;
          }

            //Проверка на правильный ввод IP-адреса
            Regex rgx = new Regex(@"^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$");

            if (rgx.IsMatch(textBox1.Text) && rgx.IsMatch(textBox2.Text))//если он правильный
            {
                if(textBox3.Text=="")
                {
                    MessageBox.Show("Введите порт или порты.");
                }
                else
                {
                    portStart = Int32.Parse(textBox3.Text);
                    portEnd = Int32.Parse(textBox4.Text);
                    progressBar1.Minimum = portStart;
                    progressBar1.Maximum = portEnd;
               }
               
            }
            else
            {
                MessageBox.Show("Проверьте правильность IP-адреса.");
                return;
            }

         
            if (portEnd < portStart)
            {
                MessageBox.Show("Радиус портов написан неправильно.");
                return;
            }
            ok = true;
            Thread waitT = new Thread(new ThreadStart(wait));
            waitT.Start();
           
        }

        public void wait()
        {
            int startIp = Int32.Parse(textBox1.Text.Split('.')[3]);
            int endIp = Int32.Parse(textBox2.Text.Split('.')[3]);

            string ip = textBox1.Text.Split('.')[0] + "." + textBox1.Text.Split('.')[1] + "." + textBox1.Text.Split('.')[2] + ".";
            for (int q = startIp; q <= endIp && ok == true; q++)
            {

                //---------------------ping
                Ping ping = new Ping();
                PingReply reply = ping.Send(IPAddress.Parse(ip + q), overTime);
            }

                for (int q = startIp; q <= endIp && ok == true; q++)
            {
                Thread[] tharr;
                if (numThread < (portEnd - portStart + 1))
                {
                    tharr = new Thread[portEnd - portStart + 1];
                }
                else
                {
                    tharr = new Thread[numThread];
                }
                str = new List<string>();
                for (int i = portStart; i <= portEnd; i++)
                {
                    Thread thread = new Thread(new ParameterizedThreadStart(Scan));
                    thread.Start(new IPEndPoint(IPAddress.Parse(ip + q), i));
                    tharr[i - portStart] = thread;
                    progressBar1.Value = i;
                    Thread.Sleep(overTime);
                    string s = State(i);
                    if (checkBox1.Checked)
                    {
                        if (s == "Открыт")
                        {

                            listBox1.Items.Add(ip + q + "                " + i + "           " + s + "   " + "          " + Service(i));
                        }
                    }
                    else
                    {
                        if (s == "Открыт")
                        {

                            listBox1.Items.Add(ip + q + "                " + i + "            " + s + "   " + "         " + Service(i));
                        }
                        else
                        {
                            listBox1.Items.Add(ip + q + "                " + i + "            " + s + "   " + "          ");
                        }
                    }

                }


                bool iscon = true;
                for (int i = 0; i < tharr.Length; i++)
                {
                    if (tharr[i] == null)
                        continue;
                    while (tharr[i].IsAlive && iscon)
                    {
                        Thread.Sleep(200);
                        iscon = false;
                    }
                }
                str.Sort();
            }
            if (ok == true)
            {
                MessageBox.Show("Сканер закончил свою работу.");
                progressBar1.Value = progressBar1.Minimum;
                
            }
            else
            {
                MessageBox.Show("error");
            }
        }
            public string State(int i)
        {
               str.Sort();
                for (int k = 0; k < str.Count; k++)
                {
                    string s = str[k];
                    if(Convert.ToString(i)==s)
                        return "Открыт";
                }
                   return "Закрыт";
        }
        public string Service(int i)
        {

            string result = "" +
                "";
            foreach (IDomObject obj in htmllink.Find("tr"))
            {
                if(obj[0].ClassName == "r" & obj[0].InnerText == Convert.ToString(i))
                {
                    result += obj[4].InnerText + " ";
                }
            }

            return result;
        }

        public void Scan(object Point)
        {
            IPEndPoint IPPoint = (IPEndPoint)Point;
            try
            {
                TcpClient tcp = new TcpClient();
                tcp.Connect(IPPoint);
                if (tcp.Connected)
                    str.Add(Convert.ToString(IPPoint.Port));
           }
            catch
            {
                ;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            button1.Enabled = true;
            button2.Enabled = false;

            ok = false;
            progressBar1.Value = progressBar1.Minimum;
            MessageBox.Show("Приложение будет остановлено и закрыто.");
            Application.ExitThread();
            Application.Exit();

        }
        private void button3_Click(object sender, EventArgs e)
        {
            Form2 f = new Form2();
            f.Show();
        }
        

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {
            if (textBox2.Visible == true)
            {
                textBox2.Visible = false;
                label2.Text = "";
            }
            else
            {
                textBox2.Visible = true;
                textBox1.Text = textBox2.Text="";
                label2.Text = "-";
            }
                
        }

        private void checkBox3_CheckedChanged(object sender, EventArgs e)
        {
            if (textBox4.Visible == true)
            {
                textBox4.Visible = false;
                label3.Text = "";
            }
            else
            {
                textBox4.Visible = true;
                textBox3.Text = textBox4.Text = "";
                label3.Text = "-";
            }
               
        }

        private void groupBox1_Enter(object sender, EventArgs e)
        {

        }
    }
}
