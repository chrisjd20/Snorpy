#!/usr/bin/env python3
#Snorpy - Python Rule Creator
#Created by Christopher Davis - github.com/chrisjd20/snorpy
#Free for use or modification under the GNU public licence

import re
import time
import codecs


banner = ("\n###################################################################\n"
          "#                 __                                              #\n"
          "#                /  \_ __   ___  _ __ _ __  _   _                 #\n"
          "#                \ \| '_ \ / _ \| '__| '_ \| | | |                #\n"
          "#                _\ \ | | | (_) | |  | |_) | |_| |                #\n"
          "#                \__/_| |_|\___/|_|  | .__/ \__, |                #\n"
          "#                                    |_|    |___/                 #\n"
          "#                Python Snort Rule Creator                        #\n"
          "#                Command Line Version                             #\n"
          "#                See Also: Snorpy.com                             #\n"
          "#                Created By Christopher Davis                     #\n"
          "#                github.com/chrisjd20/snorpy                      #\n"
          "#                                                                 #\n"
          "###################################################################\n")

snortForm = ("\n\n---------------------------Snort Rule Structure-------------------------------\n"
             "ACTION    PROTO    SRC_IP    SRC_PORT    ->    DST_IP    DST_PORT    (OPTIONS)\n"
             "  1.        2.       3.         4.               5.         6.           7.    \n\n"
             " alert tcp any any -> any any (content:\"snorpy\"; priority:1; sid:1; rev:1;) \n"
             "------------------------------------------------------------------------------\n\n"
             "Select from the following to modify\n\n"
             "1. Rule Action\n"
             "2. Protocol - UDP, ICMP, TCP, IP\n"
             "3. Source IP address/range\n"
             "4. Source 
             "5. Destination IP address/range\n"
             "6. Destination Port\n" 
             "7. Rule Options Wizard\n"
             "R. Reset Rule\n"
             "Q. Quit\n\n")

fail = (""
"           ############################\n"
"           #  _____ _    ___ _     _  #\n"
"           # |  ___/ \  |_ _| |   | | #\n"
"           # | |_ / _ \  | || |   | | #\n"
"           # |  _/ ___ \ | || |___|_| #\n"
"           # |_|/_/   \_\___|_____(_) #\n"
"           #                          #\n"
"           ############################\n"
"You Entered in Something Incorrectly. Starting Over!\n"
"                  Press Enter...\n: ")

success = [
"        ____                _         ",
"       / ___|_ __ ___  __ _| |_       ",
"      | |  _| '__/ _ \/ _` | __|      ",
"      | |_| | | |  __/ (_| | |_       ",
"  ____ \____|_|  \___|\__,_|\__|    _ ",
" / ___| _   _  ___ ___ ___  ___ ___| |",
" \___ \| | | |/ __/ __/ _ \/ __/ __| |",
"  ___) | |_| | (_| (_|  __/\__ \__ \_|",
" |____/ \__,_|\___\___\___||___/___(_)",
'.',
'.',
'.',
'.',
'.',
'.',
'.',
'.',
'.',
"__     __         _                  ",
"\ \   / /        (_)                 ",
" \ \_/ /__  _   _   _ __ ___    __ _ ",
"  \   / _ \| | | | | '__/ _ \  / _` |",
"   | | (_) | |_| | | | |  __/ | (_| |",
" _ |_|\___/ \__,_| |_|  \___|  \__,_|",
" \ \        / (_)                | | ",
"  \ \  /\  / / _ ______ _ _ __ __| | ",
"   \ \/  \/ / | |_  / _` | '__/ _` | ",
"    \  /\  /  | |/ / (_| | | | (_| | ",
"     \/  \/   |_/___\__,_|_|  \__,_| ",
'.',
'.',
'.',
'.',
'.',
'.',
'.',
'.',
'.',
" __     ___       _                 ",
" \ \   / (_) ___ | | __ _           ",
"  \ \ / /| |/ _ \| |/ _` |          ",
"   \ V / | | (_) | | (_| |_   _   _ ",
"    \_/  |_|\___/|_|\__,_(_) (_) (_)",
' ',
' ',
' ',
' ',]

ruleAction = ''
ruleProto = ''
ruleSrcIP = ''
ruleSrcPort = ''
ruleDstIP = ''
ruleDstPort = ''
ruleOptions = []
workingRule = ''
content = ''
flags = ''
httpVar = ''
icmpVar = ''
clear = '\n' * 35
direction = ''

def clearRule():
    global ruleAction; ruleAction = ''
    global ruleProto; ruleProto = ''
    global ruleSrcIP; ruleSrcIP = ''
    global ruleSrcPort; ruleSrcPort = ''
    global ruleDstIP; ruleDstIP = ''
    global ruleDstPort; ruleDstPort = ''
    global ruleOptions; ruleOptions = []
    global workingRule; workingRule = ''

def action():
    global ruleAction
    global clear
    while True:
        action = input(clear+"Select from the following Choices:\n\n"
                       "1. alert    - generate an alert and then log the packet\n"
                       "2. log      - log the packet\n"
                       "3. pass     - ignore the packet\n"
                       "4. activate - alert and then turn on another dynamic rule\n"
                       "5. dynamic  - idle until started by an activate rule then log\n"
                       "6. drop     - block and log the packet\n"
                       "7. reject   - block the packet, log it, and send TCP RST.\n"
                       "8. sdrop    - block the packet but do not log it.\n"
                       "M. Main Menu\n\n\n\n: ")
        if action == '1':
            ruleAction = 'alert '
            return
        elif action == '2':
            ruleAction = 'log '
            return
        elif action == '3':
            ruleAction = 'pass '
            return
        elif action == '4':
            ruleAction = 'activate '
            return
        elif action == '5':
            ruleAction = 'dynamic '
            return
        elif action == '6':
            ruleAction = 'drop '
            return
        elif action == '7':
            ruleAction = 'reject '
            return
        elif action == '8':
            ruleAction = 'sdrop '
            return
        elif action.lower() == 'm':
            return
        else:
            continue

def protocol():
    global ruleProto
    global clear
    while True:
        print(clear + "Please enter the desired protocol\n\n"
              '1. IP   - Any protocol using IP\n'
              '2. TCP  - Transmission Control Protocol\n'
              '3. UDP  - User Datagram Protocol\n'
              '4. ICMP - You know... Ping etc...\n'
              'M. Main Menu\n\n\n\n\n\n\n\n\n\n')
        proto = input(': ')
        if proto == '1':
            ruleProto = 'ip '; return
        if proto == '2':
            ruleProto = 'tcp '; return
        if proto == '3':
            ruleProto = 'udp '; return
        if proto == '4':
            ruleProto = 'icmp '; return
        if proto.lower() == 'm':
            return
        else:
            continue

def ipv4Checker(ip):
    if re.match(r"^((?:(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.){3}(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)(?:/[1-3][0-9])*)$",ip) is not None:
        return True
    else:
        return False

def src_ip():
    global clear
    global ruleSrcIP
    ruleSrcIP = ''
    exclude = ''
    while True:
        choice = input(clear + 'Choose from the following\n\n'
                       '1. Include IP\n'
                       '2. Exclude IP\n'
                       '3. $HOME_NET\n'
                       '4. $EXTERNAL_NET\n'
                       '5. Exclude Custome VAR\n'
                       '6. Include Custom Variable\n'
                       '7. Clear all entries for Src IP\n'
                       'M. Main Menu\n\n\n\n\n'
                       'Your Current Included src IPs are:\n'+ ruleSrcIP + '\n\nYour excluded src IPs are:\n'+exclude+'\n: ')
        if choice == '4':
            if ruleSrcIP == '':
                ruleSrcIP += '$EXTERNAL_NET'
            else:
                ruleSrcIP += ',$EXTERNAL_NET'
        elif choice == '3':
            if ruleSrcIP == '':
                ruleSrcIP += '$HOME_NET'
            else:
                ruleSrcIP += ',$HOME_NET'
        elif choice == '1':
            ip = input('Enter IP or range\n: ')
            if ipv4Checker(ip):
                if ruleSrcIP == '':
                    ruleSrcIP += ip
                else:
                    ruleSrcIP += "," + ip
            else:
                print('\nYou did not put in a correct ip or CIDR\n')
                input('Press Enter to Continue...')
        elif choice == '2':
            ip = input('Enter in the IP or Range you want to Exclude\n: ')
            if ipv4Checker(ip):
                if exclude == '':
                    exclude += ip
                else:
                    exclude += ',' + ip
            else:
                print('\nYou did not put in a correct ip or CIDR\n')
                input('Press Enter to Continue...')
        elif choice == '5':
            var = input('Enter in the Var you want to Exclude. Dont forget the $\n:')
            if exclude == '':
                exclude += var
            else:
                exclude += ','+ var
        elif choice == '6':
            var = input('Enter in your custom Variable. Dont forget the $\n:')
            if ruleSrcIP == '':
                ruleSrcIP += var
            else:
                ruleSrcIP += ','+ var
        elif choice == '7':
            ruleSrcIP = ''
            exclude = ''
        elif choice.lower() == 'm':
            if exclude == "":
                ruleSrcIP = '['+ruleSrcIP+'] '
                return
            else:
                ruleSrcIP = '[' + ruleSrcIP +(',!['+exclude+']')+'] '
                return

def dst_ip():
    global clear
    global ruleDstIP
    ruleDstIP = ''
    exclude = ''
    while True:
        choice = input(clear + 'Choose from the following\n\n'
                       '1. Include IP\n'
                       '2. Exclude IP\n'
                       '3. $HOME_NET\n'
                       '4. $EXTERNAL_NET\n'
                       '5. Exclude a CustomVAR\n'
                       '6. Include Custom Variable\n'
                       '7. Clear Entry for Src IP\n'
                       'M. Main Menu\n\n\n\n\n\n: '
                       'Your Current Included dst IPs are:\n'+ ruleDstIP + '\n\nYour excluded dst IPs are:\n'+exclude+'\n ')
        if choice == '4':
            if ruleDstIP == '':
                ruleDstIP += '$EXTERNAL_NET'
            else:
                ruleDstIP += ',$EXTERNAL_NET'
        elif choice == '3':
            if ruleDstIP == '':
                ruleDstIP += '$HOME_NET'
            else:
                ruleDstIP += ',$HOME_NET'
        elif choice == '1':
            ip = input('Enter IP or range\n: ')
            if ipv4Checker(ip):
                if ruleDstIP == '':
                    ruleDstIP += ip
                else:
                    ruleDstIP += "," + ip
            else:
                print('\nYou did not put in a correct ip or CIDR\n')
                input('Press Enter to Continue...')
        elif choice == '2':
            ip = input('Enter in the IP or Range you want to Exclude\n: ')
            if ipv4Checker(ip):
                if exclude == '':
                    exclude += ip
                else:
                    exclude += ',' + ip
            else:
                print('\nYou did not put in a correct ip or CIDR\n')
                input('Press Enter to Continue...')
        elif choice == '5':
            var = input('Enter in the Var you want to Exclude. Dont forget the $\n:')
            if exclude == '':
                exclude += var
            else:
                exclude += ','+ var
        elif choice == '6':
            var = input('Enter in your custom Variable. Dont forget the $\n:')
            if ruleDstIP == '':
                ruleDstIP += var
            else:
                ruleDstIP += ','+ var
        elif choice == '7':
            ruleDstIP = ''
            exclude = ''
        elif choice.lower() == 'm':
            if exclude == "":
                ruleDstIP = ' ['+ruleDstIP+'] '
                return
            else:
                ruleDstIP = ' [' + ruleDstIP +(',!['+exclude+']')+'] '
                return
            
def portChecker(port):
    try:
        if ':' in port:
            pRange = port.split(':')
            if len(pRange) != 2:
                return False
            else:
                if int(pRange[0]) < 1 or int(pRange[0]) > 65535 or int(pRange[1]) < 1 or int(pRange[1]) > 65535:
                    return False
                elif int(pRange[0]) > int(pRange[1]):
                    return False
                else:
                    return True
        else:
            if int(port) < 1 or int(port) > 65535:
                return False
            elif int(port) > 0 and int(port) < 65535:
                return True
    except:
        return False

def src_port():
    global ruleSrcPort
    global clear
    exclude = ''
    ruleSrcPort = ''
    while True:
        print(clear + 'Choose from the following for source ports\n '
              '\n1. Enter Port Number or Port Range\n'
              '2. Enter Port Number or range to exclude\n'
              '3. Enter Variable to Include\n'
              '4. Enter Variable to Exclude\n'
              'm. Return to Main menu\n\n\n')
        print('\nYour included ports are:\n' + ruleSrcPort + '\nYour excluded ports are:\n' + exclude)
        choice = input('\n: ')
        if choice == '3':
            if ruleSrcPort == "":
                ruleSrcPort += input('\nEnter in the var. Dont forget the $\n: ')
            else:
                ruleSrcPort += ',' + input('\nEnter in the var. Dont forget the $\n: ')
        elif choice == '4':
            if exclude == '':
                exclude += input('\nEnter in the var to exclude. Dont forget the $\n: ')
            else:
                exclude += '' + input('\nEnter in the var. Dont forget the $\n: ')
        elif choice == '1':
            port = input('Enter in the Source Port Number or range\n: ')
            if portChecker(port):
                if ruleSrcPort == "":
                    ruleSrcPort += port
                else:
                    ruleSrcPort += ',' + port
            else:
                input('You Entered an Invalid port number or port range.\nPress Enter to continue...\n: ')
        elif choice == '2':
            port = input('Enter in the Source Port Number or range to exclude\n: ')
            if portChecker(port):
                if exclude == "":
                    exclude += port
                else:
                    exclude += ',' + port
            else:
                input('You Entered an Invalid port number or port range.\nPress Enter to continue...\n: ')
        elif choice.lower() == 'm':
            if exclude == "":
                ruleSrcPort = '['+ ruleSrcPort+ '] '
                return
            else:
                ruleSrcPort = '['+ruleSrcPort+(',!['+exclude+']')+'] '
                return
            
def dst_port():
    global ruleDstPort
    global clear
    exclude = ''
    ruleDstPort = ''
    while True:
        print(clear + 'Choose from the following for destination ports\n'
              '1. Enter Port Number or Port Range\n'
              '2. Enter Port Number or range to exclude\n'
              '3. Enter Variable to Include\n'
              '4. Enter Variable to Exclude\n'
              'M. Return to Main menu\n\n\n'
              '\nYour included ports are:\n' + ruleDstPort + '\n\nYour excluded ports are:\n' + exclude)
        choice = input('\n: ')
        if choice == '3':
            if ruleDstPort == "":
                ruleDstPort += input('\nEnter in the var. Dont forget the $\n: ')
            else:
                ruleDstPort += ',' + input('\nEnter in the var. Dont forget the $\n: ')
        elif choice == '4':
            if exclude == '':
                exclude += input('\nEnter in the var to exclude. Dont forget the $\n: ')
            else:
                exclude += '' + input('\nEnter in the var. Dont forget the $\n: ')
        elif choice == '1':
            port = input('Enter in the destination Port Number or range\n: ')
            if portChecker(port):
                if ruleDstPort == "":
                    ruleDstPort += port
                else:
                    ruleDstPort += ',' + port
            else:
                input('You Entered an Invalid port number or port range.\nPress Enter to continue...\n: ')
        elif choice == '2':
            port = input('Enter in the destination Port Number or range to exclude\n: ')
            if portChecker(port):
                if exclude == "":
                    exclude += port
                else:
                    exclude += ',' + port
            else:
                input('You Entered an Invalid port number or port range.\nPress Enter to continue...\n: ')
        elif choice.lower() == 'm':
            if exclude == "":
                ruleDstPort = '['+ ruleDstPort+ '] '
                return
            else:
                ruleDstPort = '['+ruleDstPort+(',!['+exclude+']')+'] '
                return        

def mandatoryChecker(var):
    if re.match(r'(\spriority:[1-5];|\sgid:\d+;|\ssid\:\d+;|\srev:\d+;|\sclasstype:.+?;|\smsg:".+?";)',var) is not None:
        return True
    else:
        return False
    
def gidCheck(var):
    if var == '':
        return True
    elif re.match(r'(\spriority:[1-5];|\sgid:\d+;|\ssid\:\d+;|\srev:\d+;|\sclasstype:.+?;|\smsg:".+?";)',var) is not None:
        return True
    else:
        return False


def http():
    global clear
    choice = input(clear + 'Would you like to do any of the following\n'
                   '1. Track HTTP by Request Method')
def dChecker(var):
    if var == '':
        return True
    return bool(re.search(r"(\sflow:.+;|\sdsize:[<,>]\d+;|\sttl:[<,>]\d+;|\sreference:url,.+?;)", var))

def options():
    global success
    global httpVar; httpVar = ''
    global direction; direction = ''
    global clear
    global icmpVar; icmpVar = ''
    global content; content = ''
    global fail
    global flags; flags = ''
    global ruleOptions; ruleOptions = []
    global ruleProto
    print(clear + ''
"########################################################################\n"
"#                  ____                                                #\n"
"#                 / ___| _ __   ___  _ __ _ __  _   _                  #\n"
"#                 \___ \| '_ \ / _ \| '__| '_ \| | | |                 #\n"
"#                  ___) | | | | (_) | |  | |_) | |_| |                 #\n"
"#                 |____/|_| |_|\___/|_|  | .__/ \__, |                 #\n"
"#                                        |_|    |___/                  #\n"
"#   ___        _   _                  __        ___                  _ #\n"
"#  / _ \ _ __ | |_(_) ___  _ __  ___  \ \      / (_)______ _ _ __ __| |#\n"
"# | | | | '_ \| __| |/ _ \| '_ \/ __|  \ \ /\ / /| |_  / _` | '__/ _` |#\n"
"# | |_| | |_) | |_| | (_) | | | \__ \   \ V  V / | |/ / (_| | | | (_| |#\n"
"#  \___/| .__/ \__|_|\___/|_| |_|___/    \_/\_/  |_/___\__,_|_|  \__,_|#\n"
"#       |_|                                                            #\n"
"########################################################################\n\n\n\n\n")
    input("Press Enter to Begin...\n: ")
    while True:
        sid = input(clear +clear+'\n\nSid - The ID for the rule. Must be unique and a number.\n\n: ')
        sid = ' sid:'+sid+';'
        rev = input(clear+'Rev - Revisions made to rule.\nPress Enter for revision 1.\n\n: ')
        if rev == "":
            rev = ' rev:1;'
        else:
            rev = ' rev:' + rev + ';'
        msg = input(clear + 'Msg - The message to be displayed when the rule is triggered.\n\n: ')
        msg = ' msg:"'+msg+'";'
        classtype = input(clear+'Classtype - The category to be tagged when the rule is triggered\n\nEXAMPLES:\n\nATTEMPTED-USER\nWEB-APPLICATION-ATTACK\nATTEMPTED-RECON\nPOLICY-VIOLATION\nSHELLCODE-DETECT\nMISC-ATTACK\nNETWORK-SCAN\nUNKNOWN\n\n: ')
        classtype = ' classtype:'+classtype+';'
        priority = input(clear+'Priority - This sets the severity of the alert\nThis is 1-5 but typically only 1-3 are used.\n1 being severe and 3 being less severe\n\n: ')
        priority = ' priority:'+priority+';'
        gid = input(clear + 'Gid - Press enter to leave blank. (Optional)\n\n: ')
        if gid != '':
            gid = ' gid:'+gid+';'
        check = input(clear + '\nIs the following info correct?\n-------------------------------------------------------------\n\n'
                      ''+sid + '\n'
                      ''+rev + '\n'
                      ''+msg + '\n'
                      ''+classtype + '\n'
                      ''+priority + '\n'
                      ''+gid + '\n'
                      '\'Y\'es or \'N\'o?\n\n: ')
        if check.upper() == 'N':
            continue
        elif mandatoryChecker(sid) and mandatoryChecker(rev) and mandatoryChecker(msg) and mandatoryChecker(classtype) and mandatoryChecker(priority) and gidCheck(gid):
            break
        else:
            continue
    while True:
        while True:
            if ruleProto != 'icmp ':
                direction = input(clear+ 'Flow - Directional flow of data.\n\n'
                                  '1. TO_SERVER\n'
                                  '2. FROM_SERVER\n'
                                  '3. TO_CLIENT\n'
                                  '4. FROM_CLIENT\n'
                                  '5. Do not insert this option (optional)\n\n'
                                  ': ')
                if direction == '1':
                    direction = ' flow:to_server;'
                    break
                elif direction == '2':
                    direction = ' flow:from_server;'
                    break
                elif direction == '3':
                    direction = ' flow:to_client;'
                    break
                elif direction == '4':
                    direction = ' flow:from_client;'
                    break
                elif direction == '5':
                    direction = ''
                    break
                else:
                    input('\nInvalid Choice...\n')
                    continue
            else:
                break
        while True:
            dsize = input(clear + 'Data Size - As in packet data size. Ex - ">500" or "<30".\nPress enter to leave blank (optional)\n: ')
            if dsize == "":
                dsize == ""
            else:
                dsize = ' dsize:'+dsize+';'
            reference = input(clear+'Enter a URL for reference so reviewing analyst has a lead\n Press Enter to leave blank (optional)\n: ')
            if reference == '':
                reference == ''
            else:
                reference = ' reference:url,'+reference+';'
            ttl = input(clear+'ttl - Input > or < a number to trigger on ttl. I.e. ">64" or "<2" etc...\nPress Enter to leave blank (optional)\n\n: ')
            if ttl == "":
                ttl == ""
            else:
                ttl = ' ttl:'+ttl+';'
            check = input(clear+'Are the following entries correct?\n\n'
                          ''+ direction + '\n'
                          ''+ dsize + '\n'
                          ''+ ttl + '\n'
                          ''+ reference + '\n\n\'Y\'es or \'N\'o?\n\n: ')
            if check.upper() == 'N':
                continue
            elif check.upper() == 'Y':
                if dChecker(direction) and dChecker(dsize) and dChecker(reference) and dChecker(ttl):
                    break
                else:
                    print(clear+fail)
                    time.sleep(1.5)
            else:
                print(clear+fail)
                time.sleep(1.5)
        while True:
            if ruleProto == 'icmp ':
                icmpVar = icmp()
                break
            elif ruleProto == 'tcp ':
                tcp()
                break
            else:
                break
        while True:
            choice = input(clear + 'Would you like to Do A Content or Regex match on the paylod contents?\n\'Y\'es or \'N\'o?\n\n: ')
            if choice.upper() == 'Y':
                contentRE()
                break
            elif choice.upper() == 'N':
                break
        appendList = [msg,httpVar,content,direction,icmpVar,flags,ttl,dsize,reference,classtype,priority,gid,sid,rev]
        for i in appendList:
            ruleOptions.append(i)
        for i in success:
            time.sleep(.05)
            print(i)
        return


def contentRE():
    global content
    global clear
    regex = ''
    contents = ''
    print(clear+'Almost done, I swear!')
    time.sleep(1.5)
    while True:
        choice = input(clear+'Would you like to enter in a/another content or regex match?\n"C"ontent or "R"egex or "N"o\n: ')
        tempcontent = ''
        trackby = ''
        contentCount = ''
        seconds = ''
        if choice.upper() == 'C':
            contents = input(clear+'Please Enter in any string to be converted into a content match.\n: ')
            match = '\`  \~  \!  \@  \#  \$  \%  \^  \&  \*  \)  \(  \-  \_  \=  \+  \]  \[  \}  \{  \\  \;  \:  \'  \"  \,  \<  \.  \>  \/  \? '
            tmpcontents = ''
            for z in contents:
                if z in match:
                    value = False
                    break
                else:
                    value = True
            if value:
                contents = ' content:"'+contents+'";'
            else:
                contents = codecs.encode(contents.encode(),'hex_codec').decode('utf-8')
                count = 0
                for z in contents:
                    if count % 2 == 0 and count != 0:
                        tmpcontents += ' '+ z
                    else:
                        tmpcontents += z
                    count += 1
                contents = ' content:"|'+tmpcontents+'|";'
                
            while True:
                offset = ''
                depth = ''
                options = input(clear+'Would you like to input any of the following options for your content?\n\n1. Offset\n2. Depth\n3. Offset+Depth\nN. No\n: ')
                if options == '1':
                    try:
                        offset = int(input(clear+'Enter in the offset (bytes) into the payload to start the content match\n: '))
                    except:
                        continue
                    offset = ' offset:'+ str(offset)+';'
                    break
                elif options == '2':
                    try:
                        depth = int(input(clear+'Enter a number for the bytes into the payload to search within\n: '))
                    except:
                        continue
                    depth = ' depth:' + str(depth)+ ';'
                    break
                elif options == '3':
                    try:
                        offset = int(input(clear+'Enter in the offset (bytes) into the payload to start the content match\n: '))
                        depth = int(input(clear+'Enter a number for the bytes into the payload to search within\n: '))
                    except:
                        continue
                    offset = ' offset:'+ str(offset)+';'
                    depth = ' depth:' + str(depth)+ ';'
                    break
                elif options.upper() == 'N':
                    break
                else:
                    continue
            while True:
                negative = ''
                choice = input(clear+'Would you like to make this a negative content match\n"Y"es or "N"o: ')
                if choice.upper() == 'Y':
                    negative = '!'
                    break
                elif choice.upper() == 'N':
                    break
                else:
                    continue
            while True:
                nocase = ''
                choice = input(clear+'Would you like to make this content match case insensitive?\n"Y"es or "N"o: ')
                if choice.upper() == 'Y':
                    nocase = ' nocase;'
                    break
                elif choice.upper() == 'N':
                    nocase = ''
                    break
                else:
                    continue
            contents = contents[:9]+ negative+ contents[9:]
            tempcontent += contents + offset + depth + nocase
            content += tempcontent
                
        elif choice.upper() == 'R':
            tempcontent = ''
            regex = input(clear + 'Please Enter In your regex match. This will not be error checked.\nPythex.org is a good resource to build and check\n: ')
            regex = ' pcre:"/'+ regex+ '/is";'
            tempcontent += regex
            content += tempcontent
        elif choice.upper() == 'N':
            break
        else:
            continue
    while True:
        occurrence = ''
        occurrence = input(clear + 'Would you like to match on rate of occurrence?\nI.e. will only alert if content matches X packets over x seconds\n"Y"es or "N"o\n: ')
        if occurrence.upper() == 'Y':
            while True:
                trackby = input(clear+'Would you like to track by source or destination?\n"S"ource or "D"estination?\n: ')
                if trackby.upper() == "S":
                    trackby = 'by_src'
                    break
                elif trackby.upper() == "D":
                    trackby = 'by_dst'
                    break
                else:
                    continue
            while True:
                try:
                    contentCount = int(input(clear+"Enter in the amount of occurrences before rules triggers\n:"))
                    break
                except:
                    continue
            while True:
                try:
                    seconds = int(input(clear+'Over how many seconds?\n: '))
                    break
                except:
                    continue
            occurrence = ' threshold: type both , track '+trackby+', count '+str(contentCount)+' , seconds '+ str(seconds)+' ;'
            break
        elif occurrence.upper() == 'N':
            occurrence = ''
            break
        else:
            continue
    content += occurrence
    return


def typeCheck(typeCode):
    if re.match(r'((?:\<|\>|\=){0,1}(?:0|3|4|5|8|9|10|11|12|13|14|15|16|17|18|30))',typeCode) is not None:
        return True
    else:
        return False

def icmp():
    global fail
    global clear
    icmpCode = ''
    typeCode = ''
    while True:
        typeCode = input(clear+ 'ICMP Type - Can use > , <. Example   >0 , <10 , 0\nPress Enter to leave blank\n\n: ')
        if typeCode == '':
            break
        elif typeCheck(typeCode):
            typeCode = ' itype:'+typeCode+';'
            break
        else:
            input('You Entered Something incorrectly')
    while True:
        if ':3;' in typeCode:
            icmpCode = input(clear+'ICMP Code - Select from any of the following\n\n'
                  '0. Net uncreachable\n'
                  '1. Host unreachable\n'
                  '2. Protocol Unreachable\n'
                  '3. Port Unreachable\n'
                  '4. Fragmentation Needed & DF Set\n'
                  '5. Source Route Failed\n'
                  '6. Destination Network Unknown\n'
                  '7. Destination Host Unknown\n'
                  '8. Source Host Isolated\n'
                  '9. Network Administratively Prohibited\n'
                  '10. Host Administratively Prohibited\n'
                  '11. Network Uncreachable for TOS\n'
                  '12. Host Unreachable for TOS\n'
                  '13. Communication Administratively Prohibited\n'
                  'N   Do not apply a ICMP Code\n\n: ')
            if icmpCode.upper() == 'N':
                icmpCode = ''
                break
            try:
                if int(icmpCode) < 14 and int(icmpCode) > -1:
                    icmpCode = ' icode:'+icmpCode+';'
                    break
                else:
                    continue
            except:
                continue
        else:
            break
    while True:
        if ':5;' in typeCode:
            icmpCode = input(clear+'ICMP Code - Select from any of the following\n\n'
                             '0. Redirect Datagram for the Network\n'
                             '1. Redirect Datagram for the Host\n'
                             '2. Redirect Datagram for the TOS & Network\n'
                             '3. Redirect Datagram for the TOS & Host\n'
                             'N Do not apply a ICMP Code\n\n: ')
            if icmpCode.upper() == 'N':
                icmpCode = ''
                break
            try:
                if int(icmpCode) < 4 or int(icmpCode) > -1:
                    icmpCode = ' icode:'+icmpCode+';'
                    break
                else:
                    continue
            except:
                continue
        else:
            break
    while True:
        if ':11;' in typeCode:
            icmpCode = input(clear+'ICMP Code - Select from any of the following\n\n'
                            '0. Time to Live exceeded in Transit\n'
                            '1. Fragment Reassembly Time Exceeded\n'
                            'N. Do not apply a ICMP Code\n\n: ')
            if icmpCode.upper() == 'N':
                icmpCode = ''
                break
            try:
                if int(icmpCode) < 2 or int(icmpCode) > -1:
                    icmpCode = ' icode:'+icmpCode+';'
                    break
                else:
                    continue
            except:
                continue
        else:
            break
    while True:
        if ':12;' in typeCode:
            icmpCode = input(clear+'ICMP Code - Select from any of the following\n\n'
                            '0. Pointer Indicates the Error\n'
                            '1. Missing a Required Option\n'
                            '2. Bad Length'
                            'N. Do not apply an ICMP Code\n\n: ')
            if icmpCode.upper() == 'N':
                icmpCode = ''
                break
            try:
                if int(icmpCode) < 3 or int(icmpCode) > -1:
                    icmpCode = ' icode:'+icmpCode+';'
                    break
                elif icmpCode.upper() == 'N':
                    icmpCode = ''
                    break
                else:
                    continue
            except:
                continue
        else:
            break
    return (typeCode + icmpCode)

def tcp():
    global fail
    global clear
    global flags
    global httpVar
    global direction
    while True:
        while True:
            httpVar = input(clear +'HTTP - Track based on HTTP Request Method or HTTP Response Code?\n\n'
                               '1. Request Method\n'
                               '2. Response Code\n'
                               'N. No, move on\n')
            if httpVar == '1':
                method = input(clear+'Select from the following HTTP Request Methods:\n\n'
                               '1. GET\n'
                               '2. POST\n'
                               '3. HEAD\n'
                               '4. TRACE\n'
                               '5. PUT\n'
                               '6. DELETE\n'
                               '7. CONNECT\n')
                if method == '1':
                    httpVar = ' content:"GET"; http_method;'
                    break
                if method == '2':
                    httpVar = ' content:"POST"; http_method;'
                    break
                if method == '3':
                    httpVar = ' content:"HEAD"; http_method;'
                    break
                if method == '4':
                    httpVar = ' content:"TRACE"; http_method;'
                    break
                if method == '5':
                    httpVar = ' content:"PUT"; http_method;'
                    break
                if method == '6':
                    httpVar = ' content:"DELETE"; http_method;'
                    break
                if method == '7':
                    httpVar = ' content:"CONNECT"; http_method;'
                    break
                else:
                    input('\nYou did not choose a viable option\n')
                    continue
            elif httpVar == '2':
                response = input(clear+ 'Please Enter an HTTP Status Code\n\n: ')
                if response == "":
                    input('\nYou did not enter anything\n')
                    continue
                try:
                    if int(response) > 99 and int(response) < 512:
                        response = ' content:"'+response+'"; http_stat_code;'
                        httpVar = response
                        break
                    else:
                        input('\nYou did not choose a viable option\n')
                        continue
                except:
                    input('\nYou did not input a valid entry\n')
                    continue
            elif httpVar == 'N':
                break
            else:
                input('\nYou did not input a valid entry\n')
                continue
            
        while True:
            choice = input(clear+'TCP Flags - Would you like to match on specific flag combinations?\n\'Y\'es or \'N\'o?\n\n:')
            if choice.upper() == 'Y':
                flags = input(clear+'Enter in the first letter only once for each flag/modifier you want:\nEx - SA or SF or FSRP or +AUCFS. Modifiers must come first\n\n'
                              "F - FIN - Finish (LSB in TCP Flags byte)\n"
                              "S - SYN - Synchronize sequence numbers\n"
                              "R - RST - Reset\n"
                              "P - PSH - Push\n"
                              "A - ACK - Acknowledgment\n"
                              "U - URG - Urgent\n"
                              "C - CWR - Congestion Window Reduced (MSB in TCP Flags byte)\n"
                              "E - ECE - ECN-Echo (If SYN, then ECN capable. Else, CE flag in IP header is set)\n"
                              "0 - No TCP Flags Set\n\n"
                              "The following modifiers can be set to change the match criteria:\n\n"
                              "+ - match on the specified bits, plus any others\n"
                              "* - match if any of the specified bits are set\n"
                              "! - match if the specified bits are not set\n\nDont Worry About Case: ")
                if flagsChecker(flags):
                    flags = ' flags:'+flags+';'
                    break
                else:
                    input('\nYou did not input a valid entry\n')
                    continue
                
            elif choice.upper() == 'N':
                break
        if len(direction) > 0: 
            while True:
                state = input(clear+'Please enter the state of a connection\n\n'
                              '1. established\n'
                              '2. not_established\n'
                              '3. stateless\n'
                              'N. Do not put in state option\n\n: ')
                if state == '1':
                    direction = direction[:-1]+',established;'
                    break
                elif state == '2':
                    direction = direction[:-1]+',not_established;'
                    break
                elif state == '3':
                    direction = direction[:-1]+'stateless;'
                    break
                elif state.upper() == 'N':
                    state = ''
                    break
                else:
                    print('\nYou did not input a valid entry\n')
        return
        
            
def flagsChecker(flags):
    flags = flags.upper()
    if '+' in flags[1:] or '*' in flags[1:] or '!' in flags[1:]:
        return False
    for i in flags:
        if i not in 'FSRPAUCE0+*!':
            return False
        if flags.count(i) > 1:
            return False
    return True

print(clear + banner)
input("Press Enter to Begin...")
while True:
    print(clear + snortForm)
    workingRule = ruleAction + ruleProto + ruleSrcIP + ruleSrcPort + "->" + ruleDstIP + ruleDstPort + '('+(''.join(ruleOptions))+')'
    print(workingRule+'\n')
    choice = input(': ')
    if choice == '1':
        action()
    elif choice == '2':
        protocol()
    elif choice == '3':
        src_ip()
    elif choice == '4':
        src_port()
    elif choice == '5':
        dst_ip()
    elif choice == '6':
        dst_port()
    elif choice == '7':
        if len(ruleAction) > 0 and len(ruleProto) > 0 and len(ruleSrcIP) > 0 and len(ruleSrcPort) > 0 and len(ruleDstIP) > 0 and len(ruleDstPort) > 0:
            options()
        else:
            input(clear+ 'You are not allowed to enter the options wizard until fields 1-6 are complete\nPress Enter to Return to main menu....')
    elif choice.lower() == 'r':
        check = input('Are you sure you would like to reset the rule to blank?\n\'Y\'es or \'N\'o\n: ')
        if check.upper() == 'N':
            continue
        elif check.upper() == 'Y':
            clearRule()
        else:
            continue
    elif choice.upper() == 'Q':
        exit()
    else:
        print("\nInvalid Choice\n")
        continue
