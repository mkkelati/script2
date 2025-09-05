#!/bin/bash
# MK Script Manager - Main Menu (run as root)

USER_LIST_FILE="/etc/mk-script/users.txt"
[[ -f "$USER_LIST_FILE" ]] || { echo "User list missing at $USER_LIST_FILE"; exit 1; }

print_menu() {
  clear
  echo "========================================"
  echo "   MK Script Manager - Main Menu"
  echo "========================================"
  echo "1) Create User"
  echo "2) Delete User"
  echo "3) Limit User"
  echo "4) Connection Mode (SSH-SSL Tunnel)"
  echo "5) Online Users"
  echo "6) Network Traffic"
  echo "7) User Report"
  echo "8) Change Password"
  echo "9) Uninstall"
  echo "========================================"
  echo -n "Select an option [1-9]: "
}

generate_password(){ < /dev/urandom tr -dc 'A-Za-z0-9' | head -c8; }
list_users(){ nl -w2 -s ') ' "$USER_LIST_FILE"; }

# OpenVPN generation functions
newclient() {
    cp /etc/openvpn/client-common.txt ~/$1.ovpn
    echo "<ca>" >>~/$1.ovpn
    cat /etc/openvpn/easy-rsa/pki/ca.crt >>~/$1.ovpn
    echo "</ca>" >>~/$1.ovpn
    echo "<cert>" >>~/$1.ovpn
    cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >>~/$1.ovpn
    echo "</cert>" >>~/$1.ovpn
    echo "<key>" >>~/$1.ovpn
    cat /etc/openvpn/easy-rsa/pki/private/$1.key >>~/$1.ovpn
    echo "</key>" >>~/$1.ovpn
    echo "<tls-auth>" >>~/$1.ovpn
    cat /etc/openvpn/ta.key >>~/$1.ovpn
    echo "</tls-auth>" >>~/$1.ovpn
}

fun_geraovpn() {
    [[ "$respost" = @(s|S) ]] && {
        cd /etc/openvpn/easy-rsa/
        ./easyrsa build-client-full $username nopass
        newclient "$username"
        sed -e "s;auth-user-pass;<auth-user-pass>\n$username\n$password\n</auth-user-pass>;g" /root/$username.ovpn >/root/tmp.ovpn && mv -f /root/tmp.ovpn /root/$username.ovpn
    } || {
        cd /etc/openvpn/easy-rsa/
        ./easyrsa build-client-full $username nopass
        newclient "$username"
    }
} >/dev/null 2>&1

fun_bar() {
    comando[0]="$1"
    comando[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${comando[0]} >/dev/null 2>&1
        ${comando[1]} >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "\033[1;33mPlease Wait.. \033[1;37m- \033[1;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[1;31m#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[1;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "\033[1;33mPlease Wait.. \033[1;37m- \033[1;33m["
    done
    echo -e "\033[1;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
    tput cnorm
}

# Host configuration and detection
get_host_info() {
    [[ -e /etc/openvpn/server.conf ]] && {
        _Port=$(grep -w 'port' /etc/openvpn/server.conf | awk {'print $2'})
        hst=$(sed -n '8 p' /etc/openvpn/client-common.txt | awk {'print $4'})
        rmt=$(sed -n '7 p' /etc/openvpn/client-common.txt)
        hedr=$(sed -n '8 p' /etc/openvpn/client-common.txt)
        prxy=$(sed -n '9 p' /etc/openvpn/client-common.txt)
        rmt2='/VPSMANAGER?'
        rmt3='www.vivo.com.br 8088'
        prx='200.142.130.104'
        payload1='#payload "HTTP/1.0 [crlf]Host: m.youtube.com[crlf]CONNECT HTTP/1.0[crlf][crlf]|[crlf]"'
        payload2='#payload "CONNECT 127.0.0.1:1194[split][crlf] HTTP/1.0 [crlf][crlf]#"'
        vivo1="portalrecarga.vivo.com.br/recarga"
        vivo2="portalrecarga.vivo.com.br/controle/"
        vivo3="navegue.vivo.com.br/pre/"
        vivo4="navegue.vivo.com.br/controle/"
        vivo5="www.vivo.com.br"
        oi="d1n212ccp6ldpw.cloudfront.net"
        bypass="net_gateway"
        cert01="/etc/openvpn/client-common.txt"
        IP=$(hostname -I | awk '{print $1}')
        
        if [[ "$hst" == "$vivo1" ]]; then
            Host="Portal Recarga"
        elif [[ "$hst" == "$vivo2" ]]; then
            Host="Recarga controle"
        elif [[ "$hst" == "$vivo3" ]]; then
            Host="Portal Navegue"
        elif [[ "$hst" == "$vivo4" ]]; then
            Host="Nav controle"
        elif [[ "$hst" == "$IP:$_Port" ]]; then
            Host="Vivo MMS"
        elif [[ "$hst" == "$oi" ]]; then
            Host="Oi"
        elif [[ "$hst" == "$bypass" ]]; then
            Host="Modo Bypass"
        elif [[ "$hedr" == "$payload1" ]]; then
            Host="OPEN SOCKS"
        elif [[ "$hedr" == "$payload2" ]]; then
            Host="OPEN SQUID"
        else
            Host="Customizado"
        fi
    }
}

# Host configuration menu
fun_edithost() {
    get_host_info
    clear
    echo -e "\E[44;1;37m          CHANGE HOST OVPN            \E[0m"
    echo ""
    echo -e "\033[1;33mHOST IN USE\033[1;37m: \033[1;32m$Host"
    echo ""
    echo -e "\033[1;31m[\033[1;36m1\033[1;31m] \033[1;33mVIVO RECHARGE"
    echo -e "\033[1;31m[\033[1;36m2\033[1;31m] \033[1;33mVIVO NAVIGATE PRE"
    echo -e "\033[1;31m[\033[1;36m3\033[1;31m] \033[1;33mOPEN SOCKS \033[1;31m[\033[1;32mAPP MOD\033[1;31m]"
    echo -e "\033[1;31m[\033[1;36m4\033[1;31m] \033[1;33mOPEN SQUID \033[1;31m[\033[1;32mAPP MOD\033[1;31m]"
    echo -e "\033[1;31m[\033[1;36m5\033[1;31m] \033[1;33mVIVO MMS \033[1;31m[\033[1;37mAPN: \033[1;32mmms.vivo.com.br\033[1;31m]"
    echo -e "\033[1;31m[\033[1;36m6\033[1;31m] \033[1;33mMODO BYPASS \033[1;31m[\033[1;32mOPEN + INJECTOR\033[1;31m]"
    echo -e "\033[1;31m[\033[1;36m7\033[1;31m] \033[1;33mALL HOSTS \033[1;31m[\033[1;32m1 OVPN OF EACH\033[1;31m]"
    echo -e "\033[1;31m[\033[1;36m8\033[1;31m] \033[1;33mEDIT MANUALLY"
    echo -e "\033[1;31m[\033[1;36m0\033[1;31m] \033[1;33mCOME BACK"
    echo ""
    echo -ne "\033[1;32mWHICH HOST DO YOU WANT TO USE \033[1;33m?\033[1;37m "
    read respo
    [[ -z "$respo" ]] && {
        echo -e "\n\033[1;31mInvalid option!"
        sleep 2
        fun_edithost
    }
    if [[ "$respo" = '1' ]]; then
        echo -e "\n\033[1;32mCHANGING HOST!\033[0m\n"
        fun_althost() {
            sed -i "7,9"d $cert01
            sleep 1
            sed -i "7i\remote $rmt2 $_Port\nhttp-proxy-option CUSTOM-HEADER Host $vivo1\nhttp-proxy $IP 80" $cert01
        }
        fun_bar 'fun_althost'
        echo -e "\n\033[1;32mSUCCESSFULLY CHANGED HOST!\033[0m"
        fun_geraovpn
        sleep 1.5
    elif [[ "$respo" = '2' ]]; then
        echo -e "\n\033[1;32mCHANGING HOST!\033[0m\n"
        fun_althost2() {
            sed -i "7,9"d $cert01
            sleep 1
            sed -i "7i\remote $rmt2 $_Port\nhttp-proxy-option CUSTOM-HEADER Host $vivo3\nhttp-proxy $IP 80" $cert01
        }
        fun_bar 'fun_althost2'
        echo -e "\n\033[1;32mSUCCESSFULLY CHANGED HOST!\033[0m"
        fun_geraovpn
        sleep 1.5
    elif [[ "$respo" = '3' ]]; then
        echo -e "\n\033[1;32mCHANGING HOST!\033[0m\n"
        fun_althostpay1() {
            sed -i "7,9"d $cert01
            sleep 1
            sed -i "7i\remote $rmt2 $_Port\n$payload1\nhttp-proxy $IP 8080" $cert01
        }
        fun_bar 'fun_althostpay1'
        echo -e "\n\033[1;32mHOST SUCCESSFULLY CHANGED!\033[0m"
        fun_geraovpn
        sleep 1.5
    elif [[ "$respo" = '4' ]]; then
        echo -e "\n\033[1;32mCHANGING HOST!\033[0m\n"
        fun_althostpay2() {
            sed -i "7,9"d $cert01
            sleep 1
            sed -i "7i\remote $rmt2 $_Port\n$payload2\nhttp-proxy $IP 80" $cert01
        }
        fun_bar 'fun_althostpay2'
        echo -e "\n\033[1;32mHOST SUCCESSFULLY CHANGED!\033[0m"
        fun_geraovpn
        sleep 1.5
    elif [[ "$respo" = '5' ]]; then
        echo -e "\n\033[1;32mCHANGING HOST!\033[0m\n"
        fun_althost5() {
            sed -i "7,9"d $cert01
            sleep 1
            sed -i "7i\remote $rmt3\nhttp-proxy-option CUSTOM-HEADER Host $vivo3\nhttp-proxy $prx:$_Port" $cert01
        }
        fun_bar 'fun_althost5'
        echo -e "\n\033[1;32mHOST SUCCESSFULLY CHANGED!\033[0m"
        fun_geraovpn
        sleep 1.5
    elif [[ "$respo" = '6' ]]; then
        echo -e "\n\033[1;32mCHANGING HOST!\033[0m\n"
        fun_althost6() {
            sed -i "7,9"d $cert01
            sleep 1
            sed -i "7i\remote $IP $_Port\nroute $IP 255.255.255.255 net_gateway\nhttp-proxy 127.0.0.1 8989" $cert01
        }
        fun_bar 'fun_althost6'
        echo -e "\n\033[1;32mSUCCESSFULLY CHANGED HOST!\033[0m"
        fun_geraovpn
        sleep 1.5
    elif [[ "$respo" = '7' ]]; then
        [[ ! -e "$HOME/$username.ovpn" ]] && fun_geraovpn
        echo -e "\n\033[1;32mCHANGING HOST!\033[0m\n"
        fun_packhost() {
            [[ ! -d "$HOME/OVPN" ]] && mkdir $HOME/OVPN
            sed -i "7,9"d $HOME/$username.ovpn
            sleep 0.5
            sed -i "7i\remote $rmt2 $_Port\nhttp-proxy-option CUSTOM-HEADER Host $vivo1\nhttp-proxy $IP 80" $HOME/$username.ovpn
            cp $HOME/$username.ovpn /root/OVPN/$username-vivo1.ovpn
            sed -i "8"d $HOME/$username.ovpn
            sleep 0.5
            sed -i "8i\http-proxy-option CUSTOM-HEADER Host $vivo3" $HOME/$username.ovpn
            cp $HOME/$username.ovpn /root/OVPN/$username-vivo2.ovpn
            sed -i "7,9"d $HOME/$username.ovpn
            sleep 0.5
            sed -i "7i\remote $rmt3\nhttp-proxy-option CUSTOM-HEADER Host $IP:$_Port\nhttp-proxy $prx 80" $HOME/$username.ovpn
            cp $HOME/$username.ovpn /root/OVPN/$username-vivo3.ovpn
            sed -i "7,9"d $HOME/$username.ovpn
            sleep 0.5
            sed -i "7i\remote $IP $_Port\nroute $IP 255.255.255.255 net_gateway\nhttp-proxy 127.0.0.1 8989" $HOME/$username.ovpn
            cp $HOME/$username.ovpn /root/OVPN/$username-bypass.ovpn
            sed -i "7,9"d $HOME/$username.ovpn
            sleep 0.5
            sed -i "7i\remote $rmt2 $_Port\n$payload1\nhttp-proxy $IP 8080" $HOME/$username.ovpn
            cp $HOME/$username.ovpn /root/OVPN/$username-socks.ovpn
            sed -i "7,9"d $HOME/$username.ovpn
            sleep 0.5
            sed -i "7i\remote $rmt2 $_Port\n$payload2\nhttp-proxy $IP 80" $HOME/$username.ovpn
            cp $HOME/$username.ovpn /root/OVPN/$username-squid.ovpn
            cd $HOME/OVPN && zip $username.zip *.ovpn >/dev/null 2>&1 && cp $username.zip $HOME/$username.zip
            cd $HOME && rm -rf /root/OVPN >/dev/null 2>&1
        }
        fun_bar 'fun_packhost'
        echo -e "\n\033[1;32mSUCCESSFULLY CHANGED HOST!\033[0m"
        sleep 1.5
    elif [[ "$respo" = '8' ]]; then
        echo ""
        echo -e "\033[1;32mCHANGING OVPN FILE!\033[0m"
        echo ""
        echo -e "\033[1;31mATTENTION!\033[0m"
        echo ""
        echo -e "\033[1;33mTO SAVE USE KEYS \033[1;32mctrl x y\033[0m"
        sleep 4
        clear
        nano /etc/openvpn/client-common.txt
        echo ""
        echo -e "\033[1;32mSUCCESSFULLY CHANGED!\033[0m"
        fun_geraovpn
        sleep 1.5
    elif [[ "$respo" = '0' ]]; then
        echo ""
        echo -e "\033[1;31mreturning...\033[0m"
        sleep 2
    else
        echo ""
        echo -e "\033[1;31mInvalid option !\033[0m"
        sleep 2
        fun_edithost
    fi
}

create_user() {
  clear
  IP=$(hostname -I | awk '{print $1}')
  cor1='\033[41;1;37m'
  cor2='\033[44;1;37m'
  scor='\033[0m'
  
  # Main user creation interface
  tput setaf 7;tput setab 4;tput bold;printf '%30s%s%-15s\n' "Create SSH User";tput sgr0
  echo ""
  echo -ne "\033[1;32mUsername:\033[1;37m ";read username
  [[ -z $username ]] && {
      echo -e "\n${cor1}Empty or invalid username!${scor}\n"
      return
  }
  [[ "$(grep -wc $username /etc/passwd)" != '0' ]] && {
      echo -e "\n${cor1}This user already exists. try another name!${scor}\n"
      return
  }
  [[ ${username} != ?(+|-)+([a-zA-Z0-9]) ]] && {
      echo -e "\n${cor1}You entered an invalid username!${scor}"
      echo -e "${cor1}Do not use spaces, accents or special characters!${scor}\n"
      return
  }
  sizemin=$(echo ${#username})
  [[ $sizemin -lt 2 ]] && {
      echo -e "\n${cor1}You entered too short a username${scor}"
      echo -e "${cor1}use at least 4 characters!${scor}\n"
      return
  }
  sizemax=$(echo ${#username})
  [[ $sizemax -gt 10 ]] && {
      echo -e "\n${cor1}You entered a very large username"
      echo -e "${cor1}use a maximum of 10 characters!${scor}\n"
      return
  }
  echo -ne "\033[1;32mPassword:\033[1;37m ";read password
  [[ -z $password ]] && {
      echo -e "\n${cor1}Empty or invalid password!${scor}\n"
      return
  }
  sizepass=$(echo ${#password})
  [[ $sizepass -lt 4 ]] && {
      echo -e "\n${cor1}Short password!, use at least 4 characters${scor}\n"
      return
  }
  echo -ne "\033[1;32mdays to expire:\033[1;37m ";read dias
  [[ -z $dias ]] && {
      echo -e "\n${cor1}number of days empty!${scor}\n"
      return
  }
  [[ ${dias} != ?(+|-)+([0-9]) ]] && {
      echo -e "\n${cor1}You entered an invalid number of days!${scor}\n"
      return
  }
  [[ $dias -lt 1 ]] && {
      echo -e "\n${cor1}The number must be greater than zero!${scor}\n"
      return
  }
  echo -ne "\033[1;32mLimit of connections:\033[1;37m ";read sshlimiter
  [[ -z $sshlimiter ]] && {
      echo -e "\n${cor1}You left the connection limit empty!${scor}\n"
      return
  }
  [[ ${sshlimiter} != ?(+|-)+([0-9]) ]] && {
      echo -e "\n${cor1}You entered an invalid number of connections!${scor}\n"
      return
  }
  [[ $sshlimiter -lt 1 ]] && {
      echo -e "\n${cor1}Number of concurrent connections must be greater than zero!${scor}\n"
      return
  }
  final=$(date "+%Y-%m-%d" -d "+$dias days")
  gui=$(date "+%d/%m/%Y" -d "+$dias days")
  pass=$(perl -e 'print crypt($ARGV[0], "password")' $password)
  useradd -e $final -M -s /bin/false -p $pass $username >/dev/null 2>&1 &
  mkdir -p /etc/mk-script/senha
  echo "$password" >/etc/mk-script/senha/$username
  echo "$username $sshlimiter" >>"$USER_LIST_FILE"
  
  # OpenVPN generation (if available)
  [[ -e /etc/openvpn/server.conf ]] && {
      echo -ne "\033[1;32mGenerate Ovpn File \033[1;31m? \033[1;33m[s/n]:\033[1;37m "; read resp
      [[ "$resp" = @(s|S) ]] && {
          rm $username.zip $username.ovpn >/dev/null 2>&1
          echo -ne "\033[1;32mGenerate With Username and Password \033[1;31m? \033[1;33m[s/n]:\033[1;37m "
          read respost
          get_host_info
          echo -ne "\033[1;32mcurrent host\033[1;37m: \033[1;31m(\033[1;37m$Host\033[1;31m) \033[1;37m- \033[1;32mChange \033[1;31m? \033[1;33m[s/n]:\033[1;37m "; read oprc
          [[ "$oprc" = @(s|S) ]] && {
              fun_edithost
          } || {
              fun_geraovpn
          }
          gerarovpn() {
              [[ ! -e "/root/$username.zip" ]] && {
                  zip /root/$username.zip /root/$username.ovpn
                  sleep 1.5
              }
          }
          function aguarde() {
              helice() {
                  gerarovpn >/dev/null 2>&1 &
                  tput civis
                  while [ -d /proc/$! ]; do
                      for i in / - \\ \|; do
                          sleep .1
                          echo -ne "\e[1D$i"
                      done
                  done
                  tput cnorm
              }
              echo ""
              echo -ne "\033[1;31mCREATING OVPN...\033[1;33m.\033[1;31m. \033[1;32m"
              helice
              echo -e "\e[1DOK"
          }
          aguarde
          VERSION_ID=$(cat /etc/os-release | grep "VERSION_ID")
          echo ""
          [[ -d /var/www/html/openvpn ]] && {
              mv $HOME/$username.zip /var/www/html/openvpn/$username.zip >/dev/null 2>&1
              [[ "$VERSION_ID" = 'VERSION_ID="14.04"' ]] && {
                  echo -e "\033[1;32mLINK\033[1;37m: \033[1;36m$IP:81/html/openvpn/$username.zip"
              } || {
                  echo -e "\033[1;32mLINK\033[1;37m: \033[1;36m$IP:81/openvpn/$username.zip"
              }
          } || {
              echo -e "\033[1;32mAvailable in\033[1;31m" ~/"$username.zip\033[0m"
              sleep 1
          }
      }
  }
  
  # Display account information
  clear
  echo -e "\033[1;32m===================================="
  echo -e "\033[1;32m   🐉ㅤMK SCRIPT MANAGERㅤ🐉  " 
  echo -e "\033[1;32m===================================="
  echo ""
  echo -e "\033[1;31m◈─────⪧ IMPORTANT ⪦──────◈"
  echo ""
  echo -e "\033[1;32m◈⪧ 🚫ㅤNO SPAM"
  echo -e "\033[1;32m◈⪧ ⚠️ㅤNO DDOS"
  echo -e "\033[1;32m◈⪧ 🎭ㅤNO Hacking"
  echo -e "\033[1;32m◈⪧ ⛔️ㅤNO Carding"
  echo -e "\033[1;32m◈⪧ 🏴‍☠️ㅤNO Torrent"
  echo -e "\033[1;32m◈⪧ ❌ㅤNO MultiLogin"
  echo -e "\033[1;32m◈⪧ 🤷‍♂️ㅤNO Illegal Activities"
  echo ""
  echo -e "\033[1;37m◈─────⪧ SSH ACCOUNT ⪦─────◈"
  echo ""
  echo -e "\033[1;32m◈ Host / IP   :⪧  \033[1;31m$IP"
  echo -e "\033[1;32m◈ Username    :⪧  \033[1;31m$username"
  echo -e "\033[1;32m◈ Password    :⪧  \033[1;31m$password"
  echo -e "\033[1;32m◈ Login Limit :⪧  \033[1;31m$sshlimiter"
  echo -e "\033[1;32m◈ Expire Date :⪧  \033[1;31m$gui"
  echo ""
  echo -e "\033[1;37m◈──────⪧ PORTS ⪦ ───────◈"
  echo ""
  echo -e "\033[1;32m◈ SSH	   ⌁  22"
  echo -e "\033[1;32m◈ SSL	   ⌁  443"
  echo -e "\033[1;32m◈ Squid    ⌁  8080"
  echo -e "\033[1;32m◈ DropBear ⌁  80"
  echo -e "\033[1;32m◈ BadVPN   ⌁  7300"
  echo ""
  echo -e "\033[1;37m◈───⪧ONLINE USER COUNT⪦────◈ "
  echo ""
  echo -e "\033[1;32mhttp://$IP:8888/server/online"
  echo ""
  echo -e "\033[1;37m◈─────────────────────────────────◈"
  echo -e "\033[1;37m©️ 🐉  MK SCRIPT MANAGER  🐉"
  echo -e "\033[1;37m◈─────────────────────────────────◈"
}

# OpenVPN user removal function
remove_ovp() {
    if [[ -e /etc/debian_version ]]; then
        GROUPNAME=nogroup
    fi
    user="$1"
    cd /etc/openvpn/easy-rsa/
    ./easyrsa --batch revoke $user
    ./easyrsa gen-crl
    rm -rf pki/reqs/$user.req
    rm -rf pki/private/$user.key
    rm -rf pki/issued/$user.crt
    rm -rf /etc/openvpn/crl.pem
    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
    chown nobody:$GROUPNAME /etc/openvpn/crl.pem
    [[ -e $HOME/$user.ovpn ]] && rm $HOME/$user.ovpn > /dev/null 2>&1
    [[ -e /var/www/html/openvpn/$user.zip ]] && rm /var/www/html/openvpn/$user.zip > /dev/null 2>&1
} > /dev/null 2>&1

delete_user() {
    database="$USER_LIST_FILE"
    clear
    tput setaf 7 ; tput setab 4 ; tput bold ; printf '%32s%s%-13s\n' "ㅤ🗑️ㅤ🐉ㅤRemove SSH Userㅤ🚮ㅤ🐉ㅤ" ; tput sgr0
    echo ""
    echo -e "\033[1;31m[\033[1;36m1\033[1;31m]\033[1;33m REMOVE A USER"
    echo -e "\033[1;31m[\033[1;36m2\033[1;31m]\033[1;33m REMOVE ALL USERS"
    echo -e "\033[1;31m[\033[1;36m3\033[1;31m]\033[1;33m COME BACK"
    echo ""
    read -p "$(echo -e "\033[1;32m◇ WHAT DO YOU WANT TO DO\033[1;31m ?\033[1;37m : ")" -e -i 1 resp
    
    if [[ "$resp" = "1" ]]; then
        clear
        tput setaf 7 ; tput setab 4 ; tput bold ; printf '%32s%s%-13s\n' "ㅤ🗑️ㅤ🐉ㅤRemove SSH Userㅤ🚮ㅤ🐉ㅤ" ; tput sgr0
        echo ""
        echo -e "\033[1;33m◇ LIST OF USERS: \033[0m"
        echo ""
        _userT=$(awk -F: '$3>=1000 {print $1}' /etc/passwd | grep -v nobody)
        i=0
        unset _userPass
        while read _user; do
            i=$(expr $i + 1)
            _oP=$i
            [[ $i == [1-9] ]] && i=0$i && oP+=" 0$i"
            echo -e "\033[1;31m[\033[1;36m$i\033[1;31m] \033[1;37m- \033[1;32m$_user\033[0m"
            _userPass+="\n${_oP}:${_user}"
        done <<< "${_userT}"
        echo ""
        num_user=$(awk -F: '$3>=1000 {print $1}' /etc/passwd | grep -v nobody | wc -l)
        echo -ne "\033[1;32m◇ Enter or select a user \033[1;33m[\033[1;36m1\033[1;31m-\033[1;36m$num_user\033[1;33m]\033[1;37m: " ; read option
        user=$(echo -e "${_userPass}" | grep -E "\b$option\b" | cut -d: -f2)
        
        if [[ -z $option ]]; then
            tput setaf 7 ; tput setab 1 ; tput bold ; echo "" ; echo " ◇ User is empty or invalid!   " ; echo "" ; tput sgr0
            return
        elif [[ -z $user ]]; then
            tput setaf 7 ; tput setab 1 ; tput bold ; echo "" ; echo "◇ User is empty or invalid! " ; echo "" ; tput sgr0
            return
        else
            if cat /etc/passwd |grep -w $user > /dev/null; then
                echo ""
                pkill -f "$user" > /dev/null 2>&1
                deluser --force $user > /dev/null 2>&1
                echo -e "\E[41;1;37m◇ User $user successfully removed! \E[0m"
                grep -v ^$user[[:space:]] "$database" > /tmp/ph ; cat /tmp/ph > "$database"
                rm /etc/mk-script/senha/$user 1>/dev/null 2>/dev/null
                LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
                [[ -f "$LIMIT_FILE" ]] && sed -i "/^${user}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE"
                if [[ -e /etc/openvpn/server.conf ]]; then
                    remove_ovp $user
                fi
                return
            elif [[ "$(cat "$database"| grep -w $user| wc -l)" -ne "0" ]]; then
                ps x | grep $user | grep -v grep | grep -v pt > /tmp/rem
                if [[ `grep -c $user /tmp/rem` -eq 0 ]]; then
                    deluser --force $user > /dev/null 2>&1
                    echo ""
                    echo -e "\E[41;1;37m◇ User $user successfully removed! \E[0m"
                    grep -v ^$user[[:space:]] "$database" > /tmp/ph ; cat /tmp/ph > "$database"
                    rm /etc/mk-script/senha/$user 1>/dev/null 2>/dev/null
                    LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
                    [[ -f "$LIMIT_FILE" ]] && sed -i "/^${user}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE"
                    if [[ -e /etc/openvpn/server.conf ]]; then
                        remove_ovp $user
                    fi
                    return
                else
                    echo ""
                    tput setaf 7 ; tput setab 4 ; tput bold ; echo "" ; echo "◇ User logged in. Disconnecting..." ; tput sgr0
                    pkill -f "$user" > /dev/null 2>&1
                    deluser --force $user > /dev/null 2>&1
                    echo -e "\E[41;1;37m◇ User $user successfully removed! \E[0m"
                    grep -v ^$user[[:space:]] "$database" > /tmp/ph ; cat /tmp/ph > "$database"
                    rm /etc/mk-script/senha/$user 1>/dev/null 2>/dev/null
                    LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
                    [[ -f "$LIMIT_FILE" ]] && sed -i "/^${user}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE"
                    if [[ -e /etc/openvpn/server.conf ]]; then
                        remove_ovp $user
                    fi
                    return
                fi
            else
                tput setaf 7 ; tput setab 4 ; tput bold ; echo "" ; echo "◇ The User $user does not exist!" ; echo "" ; tput sgr0
            fi
        fi
    elif [[ "$resp" = "2" ]]; then
        clear
        tput setaf 7 ; tput setab 4 ; tput bold ; printf '%32s%s%-13s\n' "ㅤ🗑️ㅤ🐉ㅤRemove SSH Userㅤ🚮ㅤ🐉ㅤ" ; tput sgr0
        echo ""
        echo -ne "\033[1;33m◇ YOU REALLY WANT TO REMOVE ALL USERS \033[1;37m[s/n]: "; read opc	
        if [[ "$opc" = "s" ]]; then
            echo -e "\n\033[1;33m◇ Please Wait...\033[1;32m.\033[1;31m.\033[1;33m.\033[0m"
            for user in $(cat /etc/passwd |awk -F : '$3 > 900 {print $1}' |grep -vi "nobody"); do
                pkill -f $user > /dev/null 2>&1
                deluser --force $user > /dev/null 2>&1
                if [[ -e /etc/openvpn/server.conf ]]; then
                    remove_ovp $user
                fi
                rm /etc/mk-script/senha/$user 1>/dev/null 2>/dev/null
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
                [[ -f "$LIMIT_FILE" ]] && sed -i "/^${user}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE"
            done
            rm "$database" && touch "$database"
            rm *.zip > /dev/null 2>&1
            echo -e "\n\033[1;32m◇SUCCESSFULLY REMOVED USERS!\033[0m"
            sleep 2
        else
            echo -e "\n\033[1;31m◇ Returning to the menu...\033[0m"
            sleep 2
        fi
    elif [[ "$resp" = "3" ]]; then
        echo -e "\n\033[1;31m◇ Returning to the menu...\033[0m"
        sleep 1
        return
    else
        echo -e "\n\033[1;31m◇ Invalid option!\033[0m"
        sleep 1.5s
    fi
}

limit_user() {
    database="$USER_LIST_FILE"
    clear
    tput setaf 7 ; tput setab 4 ; tput bold ; printf '%20s%s\n' "ㅤㅤChange limit on simultaneous connectionsㅤㅤ" ; tput sgr0
    echo ""
    
    if [ ! -f "$database" ]; then
        echo -e "\033[1;31m◇ User database not found!\033[0m"
        echo -e "\033[1;33m◇ Please create users first.\033[0m"
        sleep 2
        return
    fi
    
    # Check if there are users in the database
    if [[ ! -s "$database" ]]; then
        echo -e "\033[1;31m◇ No users found in database!\033[0m"
        echo -e "\033[1;33m◇ Please create users first.\033[0m"
        sleep 2
        return
    fi
    
    echo -e "\033[1;33m◇ LIST OF USERS AND CURRENT LIMITS: \033[0m"
    echo ""
    
    # Display users with current limits
    i=0
    unset _userLimits
    while IFS=' ' read -r username current_limit; do
        [[ -z "$username" ]] && continue
        i=$(expr $i + 1)
        _oP=$i
        [[ $i == [1-9] ]] && i=0$i
        
        # Display limit status
        if [[ "$current_limit" == "0" ]] || [[ -z "$current_limit" ]]; then
            limit_status="\033[1;32mUnlimited\033[0m"
        else
            limit_status="\033[1;31m$current_limit connections\033[0m"
        fi
        
        echo -e "\033[1;31m[\033[1;36m$i\033[1;31m] \033[1;37m- \033[1;32m$username \033[1;37m(\033[0m$limit_status\033[1;37m)\033[0m"
        _userLimits+="\n${_oP}:${username}:${current_limit}"
    done < "$database"
    
    [[ $i == 0 ]] && {
        echo -e "\033[1;31m◇ No users found!\033[0m"
        sleep 2
        return
    }
    
    echo ""
    echo -ne "\033[1;32m◇ Select user to modify limit \033[1;33m[\033[1;36m1\033[1;31m-\033[1;36m$i\033[1;33m]\033[1;37m: " ; read option
    
    # Validate user selection
    if [[ -z $option ]]; then
        echo -e "\n\033[1;31m◇ Invalid selection!\033[0m"
        sleep 2
        return
    fi
    
    selected_user=$(echo -e "${_userLimits}" | grep -E "^$option:" | cut -d: -f2)
    current_limit=$(echo -e "${_userLimits}" | grep -E "^$option:" | cut -d: -f3)
    
    if [[ -z $selected_user ]]; then
        echo -e "\n\033[1;31m◇ Invalid user selection!\033[0m"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "\033[1;33m◇ Selected User: \033[1;32m$selected_user\033[0m"
    
    if [[ "$current_limit" == "0" ]] || [[ -z "$current_limit" ]]; then
        echo -e "\033[1;33m◇ Current Limit: \033[1;32mUnlimited\033[0m"
    else
        echo -e "\033[1;33m◇ Current Limit: \033[1;31m$current_limit connections\033[0m"
    fi
    
    echo ""
    echo -e "\033[1;33m◇ Enter new connection limit:"
    echo -e "\033[1;37m  • \033[1;32m0\033[1;37m = Unlimited connections"
    echo -e "\033[1;37m  • \033[1;32m1-999\033[1;37m = Maximum simultaneous connections"
    echo ""
    echo -ne "\033[1;32m◇ New limit \033[1;33m[\033[1;36m0-999\033[1;33m]\033[1;37m: " ; read new_limit
    
    # Validate limit input
    if [[ -z "$new_limit" ]]; then
        echo -e "\n\033[1;31m◇ Limit cannot be empty!\033[0m"
        sleep 2
        return
    fi
    
    # Check if input is numeric
    if ! [[ "$new_limit" =~ ^[0-9]+$ ]]; then
        echo -e "\n\033[1;31m◇ Limit must be a number!\033[0m"
        sleep 2
        return
    fi
    
    # Check limit range
    if [[ $new_limit -lt 0 ]] || [[ $new_limit -gt 999 ]]; then
        echo -e "\n\033[1;31m◇ Limit must be between 0-999!\033[0m"
        sleep 2
        return
    fi
    
    # Update database
    echo ""
    echo -e "\033[1;33m◇ Updating user limit...\033[0m"
    
    # Create temporary file and update limit
    awk -v user="$selected_user" -v newlimit="$new_limit" '
        $1 == user { $2 = newlimit }
        { print $1, $2 }
    ' "$database" > "${database}.tmp" && mv "${database}.tmp" "$database"
    
    # Update PAM limits
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
  mkdir -p /etc/security/limits.d
    
    # Remove existing limit for this user
    sed -i "/^${selected_user}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE" 2>/dev/null
    
    # Add new limit if not unlimited
    if [[ "$new_limit" -gt 0 ]]; then
        echo "${selected_user}    -    maxlogins    $new_limit" >> "$LIMIT_FILE"
        echo -e "\033[1;32m◇ Successfully set limit for user '$selected_user' to $new_limit connections!\033[0m"
    else
        echo -e "\033[1;32m◇ Successfully set unlimited connections for user '$selected_user'!\033[0m"
    fi
    
    echo ""
    echo -e "\033[1;33m◇ Changes will take effect on next login.\033[0m"
    echo -e "\033[1;33m◇ Active sessions are not affected until reconnection.\033[0m"
    sleep 3
}

show_network_traffic() {
    clear
    tput setaf 7 ; tput setab 4 ; tput bold ; printf '%35s%s%-15s\n' "ㅤ📊ㅤNETWORK TRAFFICㅤ📊ㅤ" ; tput sgr0
    echo ""
    echo -e "\033[1;33m◇ Real-time Network Traffic Monitor\033[0m"
    echo ""
    echo -e "\033[1;32m◇ TO GET OUT PRESS:- CTRL + C\033[1;36m"
    echo ""
    echo -e "\033[1;37m◇ Loading network interface monitor...\033[0m"
    sleep 4
    
    # Check if nload is installed
    if ! command -v nload &> /dev/null; then
        echo ""
        echo -e "\033[1;31m◇ nload is not installed!\033[0m"
        echo -e "\033[1;33m◇ Installing nload...\033[0m"
        apt-get update -qq && apt-get install -y nload > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "\033[1;32m◇ nload installed successfully!\033[0m"
            sleep 2
        else
            echo -e "\033[1;31m◇ Failed to install nload!\033[0m"
            echo -e "\033[1;33m◇ Please install it manually: apt-get install nload\033[0m"
            sleep 3
            return
        fi
    fi
    
    # Launch nload
    nload
}

show_user_report() {
    clear
    tput setaf 7 ; tput setab 4 ; tput bold ; printf '%35s%s%-15s\n' "ㅤ📋ㅤUSER REPORTㅤ📋ㅤ" ; tput sgr0
    echo ""
    echo -e "\E[44;1;37m◇User        ◇Password      ◇limit     ◇validity \E[0m"
    echo ""
    
    # Create directories if they don't exist
    mkdir -p /etc/mk-script/senha
    mkdir -p /etc/VPSManager
    
    # Check if expired users file exists, if not create it
    [[ ! -e /etc/VPSManager/Exp ]] && echo "0" > /etc/VPSManager/Exp
    
    for users in `awk -F : '$3 > 900 { print $1 }' /etc/passwd |sort |grep -v "nobody" |grep -vi polkitd |grep -vi system-`
    do
        # Get user limit from database
        if [[ $(grep -cw $users "$USER_LIST_FILE") == "1" ]]; then
            lim=$(grep -w $users "$USER_LIST_FILE" | cut -d' ' -f2)
        else
            lim="1"
        fi
        
        # Get user password
        if [[ -e "/etc/mk-script/senha/$users" ]]; then
            senha=$(cat /etc/mk-script/senha/$users)
        elif [[ -e "/etc/VPSManager/senha/$users" ]]; then
            senha=$(cat /etc/VPSManager/senha/$users)
        else
            senha="Null"
        fi
        
        # Get user expiration date
        datauser=$(chage -l $users 2>/dev/null |grep -i co |awk -F : '{print $2}')
        if [ "$datauser" = " never" ] 2> /dev/null || [ -z "$datauser" ]
        then
            data="\033[1;33mNever\033[0m"
        else
            databr="$(date -d "$datauser" +"%Y%m%d" 2>/dev/null)"
            hoje="$(date -d today +"%Y%m%d")"
            if [ "$hoje" -ge "$databr" ] 2>/dev/null
            then
                data="\033[1;31mExpired\033[0m"
            else
                dat="$(date -d"$datauser" '+%Y-%m-%d' 2>/dev/null)"
                if [ $? -eq 0 ]; then
                    days_left=$((($(date -ud $dat +%s)-$(date -ud $(date +%Y-%m-%d) +%s))/86400))
                    data=$(echo -e "$days_left \033[1;37mDays\033[0m")
                else
                    data="\033[1;33mUnknown\033[0m"
                fi
            fi
        fi
        
        # Format output
        Usuario=$(printf ' %-15s' "$users")
        Senha=$(printf '%-13s' "$senha")
        Limite=$(printf '%-10s' "$lim")
        Data=$(printf '%-1s' "$data")
        echo -e "\033[1;33m$Usuario \033[1;37m$Senha \033[1;37m$Limite \033[1;32m$Data\033[0m"
        echo -e "\033[0;34m◇────────────────────────────────────────────────◇\033[0m"
    done
    
    echo ""
    
    # Calculate statistics
    _tuser=$(awk -F: '$3>=1000 {print $1}' /etc/passwd | grep -v nobody | wc -l)
    _ons=$(ps -x | grep sshd | grep -v root | grep priv | wc -l)
    
    # Get expired users count
    [[ "$(cat /etc/VPSManager/Exp 2>/dev/null)" != "" ]] && _expuser=$(cat /etc/VPSManager/Exp) || _expuser="0"
    
    # Count OpenVPN connections
    [[ -e /etc/openvpn/openvpn-status.log ]] && _onop=$(grep -c "10.8.0" /etc/openvpn/openvpn-status.log 2>/dev/null) || _onop="0"
    
    # Count Dropbear connections
    if [[ -e /etc/default/dropbear ]]; then
        _drp=$(ps aux | grep dropbear | grep -v grep | wc -l)
        _ondrp=$(($_drp - 1))
        [[ $_ondrp -lt 0 ]] && _ondrp="0"
    else
        _ondrp="0"
    fi
    
    # Total online users
    _onli=$(($_ons + $_onop + $_ondrp))
    
    echo -e "\033[1;33m◇ \033[1;36mTOTAL USERS\033[1;37m $_tuser \033[1;33m◇ \033[1;32mONLINE\033[1;37m: $_onli \033[1;33m◇ \033[1;31mEXPIRED\033[1;37m: $_expuser \033[1;33m◇\033[0m"
    echo ""
}

change_user_password() {
    clear
    tput setaf 7 ; tput setab 4 ; tput bold ; printf '%35s%s%-10s\n' "🐉ㅤChange User Passwordㅤ🐉" ; tput sgr0
    echo ""
    echo -e "\033[1;33mLIST OF USERS AND THEIR PASSWORDS: \033[0m"
    echo ""
    
    # Create directories if they don't exist
    mkdir -p /etc/mk-script/senha
    mkdir -p /etc/VPSManager/senha
    
    _userT=$(awk -F: '$3>=1000 {print $1}' /etc/passwd | grep -v nobody)
    i=0
    unset _userPass
    
    while read _user; do
        i=$(expr $i + 1)
        _oP=$i
        [[ $i == [1-9] ]] && i=0$i && oP+=" 0$i"
        
        # Get user password from both possible locations
        if [[ -e "/etc/mk-script/senha/$_user" ]]; then
            _senha="$(cat /etc/mk-script/senha/$_user)"
        elif [[ -e "/etc/VPSManager/senha/$_user" ]]; then
            _senha="$(cat /etc/VPSManager/senha/$_user)"
        else
            _senha='Null'
        fi
        
        suser=$(echo -e "\033[1;31m[\033[1;36m$i\033[1;31m] \033[1;37m- \033[1;32m$_user\033[0m")
        ssenha=$(echo -e "\033[1;33mPassword\033[1;37m: $_senha")
        printf '%-60s%s\n' "$suser" "$ssenha"
        _userPass+="\n${_oP}:${_user}"
    done <<< "${_userT}"
    
    num_user=$(awk -F: '$3>=1000 {print $1}' /etc/passwd | grep -v nobody | wc -l)
    echo ""
    echo -ne "\033[1;32mEnter or select a user \033[1;33m[\033[1;36m1\033[1;31m-\033[1;36m$num_user\033[1;33m]\033[1;37m: " ; read option
    user=$(echo -e "${_userPass}" | grep -E "\b$option\b" | cut -d: -f2)
    
    if [[ -z $option ]]; then
        tput setaf 7 ; tput setab 1 ; tput bold ; echo "" ; echo "Empty or invalid field!" ; echo "" ; tput sgr0
        return
    elif [[ -z $user ]]; then
        tput setaf 7 ; tput setab 1 ; tput bold ; echo "" ; echo "You entered an empty or invalid name!" ; echo "" ; tput sgr0
        return
    else
        if [[ `grep -c /$user: /etc/passwd` -ne 0 ]]; then
            echo -ne "\n\033[1;32mNew password for user \033[1;33m$user\033[1;37m: "; read password
            sizepass=$(echo ${#password})
            if [[ $sizepass -lt 4 ]]; then
                tput setaf 7 ; tput setab 1 ; tput bold ; echo "" ; echo "Empty or invalid password! use at least 4 characters" ; echo "" ; tput sgr0
                return
            else
                ps x | grep $user | grep -v grep | grep -v pt > /tmp/rem
                if [[ `grep -c $user /tmp/rem` -eq 0 ]]; then
                    echo "$user:$password" | chpasswd
                    echo ""
                    tput setaf 7 ; tput setab 2 ; tput bold ; echo "User password $user has been changed to: $password" ; tput sgr0
                    echo ""
                    
                    # Update password in both locations for compatibility
                    echo "$password" > /etc/mk-script/senha/$user
                    echo "$password" > /etc/VPSManager/senha/$user 2>/dev/null
                    
                    # Update database if user exists there
                    if [[ -f "$USER_LIST_FILE" ]] && grep -q "^$user " "$USER_LIST_FILE"; then
                        echo -e "\033[1;33m◇ Database updated successfully!\033[0m"
                    fi
                    
                    sleep 2
                else
                    echo ""
                    tput setaf 7 ; tput setab 4 ; tput bold ; echo "User logged in. Disconnecting..." ; tput sgr0
                    pkill -f $user
                    echo "$user:$password" | chpasswd
                    echo ""
                    tput setaf 7 ; tput setab 2 ; tput bold ; echo "User password $user has been changed to: $password" ; tput sgr0
                    echo ""
                    
                    # Update password in both locations for compatibility
                    echo "$password" > /etc/mk-script/senha/$user
                    echo "$password" > /etc/VPSManager/senha/$user 2>/dev/null
                    
                    # Update database if user exists there
                    if [[ -f "$USER_LIST_FILE" ]] && grep -q "^$user " "$USER_LIST_FILE"; then
                        echo -e "\033[1;33m◇ Database updated successfully!\033[0m"
                    fi
                    
                    sleep 2
                fi
            fi
        else
            tput setaf 7 ; tput setab 4 ; tput bold ; echo "" ; echo "The user $user does not exist!" ; echo "" ; tput sgr0
            sleep 2
        fi
    fi
}

configure_tunnel() {
  echo ">> Configure SSH-SSL Tunnel <<"
  read -p "Port for stunnel [default 443]: " port
  port=${port:-443}
  [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 && "$port" -le 65535 ]] || { echo "Invalid port."; return; }
  if ! command -v stunnel &>/dev/null; then
    apt-get update -y && apt-get install -y stunnel4 || { echo "stunnel install failed."; return; }
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  fi
  if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
    echo "[*] Generating stunnel certificate..."
    openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
      -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
      -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem
    cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > /etc/stunnel/stunnel.pem
    chmod 600 /etc/stunnel/stunnel.pem
  fi
  cat > /etc/stunnel/stunnel.conf <<EOC
sslVersion = TLSv1.3
ciphersuites = TLS_AES_256_GCM_SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1
options = NO_TLSv1.2
options = NO_COMPRESSION
options = NO_TICKET

[ssh-tunnel]
accept = ${port}
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
EOC
  systemctl enable stunnel4
  systemctl restart stunnel4
  echo "[*] SSH-SSL tunneling enabled on port $port."
}

show_online_users() {
    # Configuration - Using proven working paths
    local DATABASE="$USER_LIST_FILE"
    local OPENVPN_STATUS="/etc/openvpn/openvpn-status.log"
    local AUTH_LOG="/var/log/auth.log"
    local REFRESH_INTERVAL=3
    
    # Colors for display
    local RED='\033[1;31m'
    local GREEN='\033[1;32m'
    local YELLOW='\033[1;33m'
    local BLUE='\033[1;36m'
    local WHITE='\033[1;37m'
    local RESET='\033[0m'
    
    # Function to safely get numeric value (prevents arithmetic errors)
    safe_number() {
        local value="$1"
        if [[ "$value" =~ ^[0-9]+$ ]]; then
            echo "$value"
        else
            echo "0"
        fi
    }
    
    # Function to monitor Dropbear connections - Proven Working Version
    monitor_dropbear() {
        local user="$1"
        local port_dropbear=$(ps aux | grep dropbear | awk 'NR==1 {print $17}')
        local log="$AUTH_LOG"
        local loginsukses='Password auth succeeded'
        local count=0
        
        if [[ -z "$port_dropbear" ]]; then
            echo "0"
            return
        fi
        
        local pids=$(ps ax | grep dropbear | grep " $port_dropbear" | awk '{print $1}')
        
        for pid in $pids; do
            local pidlogs=$(grep "$pid" "$log" 2>/dev/null | grep "$loginsukses" | awk '{print $3}')
            local pidend=""
            
            for pidend_item in $pidlogs; do
                pidend="$pidend_item"
            done
            
            if [[ -n "$pidend" ]]; then
                local login=$(grep "$pid" "$log" 2>/dev/null | grep "$pidend" | grep "$loginsukses")
                local logged_user=$(echo "$login" | awk '{print $10}' | sed -r "s/'//g")
                
                if [[ "$logged_user" == "$user" ]]; then
                    ((count++))
                fi
            fi
        done
        
        echo "$count"
    }
    
    # Function to get SSH connection count for a user - Proven Working Version
    get_ssh_connections() {
        local user="$1"
        if grep -q "^$user:" /etc/passwd 2>/dev/null; then
            ps -u "$user" 2>/dev/null | grep -c sshd || echo "0"
        else
            echo "0"
        fi
    }
    
    # Function to get OpenVPN connection count for a user - Proven Working Version
    get_openvpn_connections() {
        local user="$1"
        if [[ -e "$OPENVPN_STATUS" ]]; then
            grep -E ",$user," "$OPENVPN_STATUS" 2>/dev/null | wc -l || echo "0"
        else
            echo "0"
        fi
    }
    
    # Function to get connection time for SSH - Proven Working Version
    get_ssh_time() {
        local user="$1"
        local ssh_pid=$(ps -u "$user" 2>/dev/null | grep sshd | awk 'NR==1 {print $1}')
        
        if [[ -n "$ssh_pid" ]]; then
            local etime=$(ps -o etime= -p "$ssh_pid" 2>/dev/null | tr -d ' ')
            local time_length=${#etime}
            
            if [[ "$time_length" -le 8 ]]; then
                echo "00:$etime"
            else
                echo "$etime"
            fi
        else
            echo "00:00:00"
        fi
    }
    
    # Function to get connection time for OpenVPN - Proven Working Version
    get_openvpn_time() {
        local user="$1"
        if [[ -e "$OPENVPN_STATUS" ]]; then
            local start_time=$(grep -w "$user" "$OPENVPN_STATUS" 2>/dev/null | awk '{print $4}' | head -1)
            local current_time=$(printf '%(%H:%M:%S)T\n')
            
            if [[ -z "$start_time" ]]; then
                echo "00:00:00"
                return
            fi
            
            # Parse start time
            local start_hour=$(echo "$start_time" | cut -c 1-2)
            local start_min=$(echo "$start_time" | cut -c 4-5)
            local start_sec=$(echo "$start_time" | cut -c 7-8)
            
            # Parse current time
            local curr_hour=$(echo "$current_time" | cut -c 1-2)
            local curr_min=$(echo "$current_time" | cut -c 4-5)
            local curr_sec=$(echo "$current_time" | cut -c 7-8)
            
            # Convert to seconds
            local start_total=$((start_hour * 3600 + start_min * 60 + start_sec))
            local curr_total=$((curr_hour * 3600 + curr_min * 60 + curr_sec))
            
            # Calculate difference
            local diff_seconds=$((curr_total - start_total))
            
            # Handle day rollover
            if [[ $diff_seconds -lt 0 ]]; then
                diff_seconds=$((diff_seconds + 86400))
            fi
            
            # Convert back to HH:MM:SS
            local hours=$((diff_seconds / 3600))
            local minutes=$(((diff_seconds % 3600) / 60))
            local seconds=$((diff_seconds % 60))
            
            printf "%02d:%02d:%02d\n" $hours $minutes $seconds
        else
            echo "00:00:00"
        fi
    }
    
    # Function to display user monitoring data - Simplified Proven Working Version
    display_user_monitor() {
        # Check if database exists
        if [[ ! -f "$DATABASE" ]]; then
            echo -e "${BLUE}│${RED} ❌ No user database found at: $DATABASE              ${BLUE}│${RESET}"
            echo -e "${BLUE}│${YELLOW} ℹ️  Please create users first using option 1                ${BLUE}│${RESET}"
            echo -e "${BLUE}└────────────────────────────────────────────────────────────┘${RESET}"
            return 1
        fi
        
        # Initialize counters
        local total_users=0
        local online_users=0
        
        # Read users from database and monitor each one - EXACTLY like the proven working code
        while IFS= read -r line; do
            if [[ -z "$line" ]]; then
                continue
            fi
            
            local user=$(echo "$line" | cut -d' ' -f1)
            local limit=$(echo "$line" | cut -d' ' -f2)
            
            # Skip if user is empty
            if [[ -z "$user" ]]; then
                continue
            fi
            
            ((total_users++))
            
            # Get connection counts - Simple and proven working
            local ssh_count=$(safe_number "$(get_ssh_connections "$user")")
            local dropbear_count=$(safe_number "$(monitor_dropbear "$user")")
            local openvpn_count=$(safe_number "$(get_openvpn_connections "$user")")
            
            # Calculate total connections
            local total_connections=$((ssh_count + dropbear_count + openvpn_count))
            
            # Determine status and time
            local status
            local connection_time
            
            if [[ $total_connections -eq 0 ]]; then
                status="${RED}Offline${RESET}"
                connection_time="00:00:00"
            else
                status="${GREEN}Online${RESET}"
                ((online_users++))
                
                # Get time from active connection (prioritize SSH, then OpenVPN)
                if [[ $ssh_count -gt 0 ]]; then
                    connection_time=$(get_ssh_time "$user")
                elif [[ $openvpn_count -gt 0 ]]; then
                    connection_time=$(get_openvpn_time "$user")
                else
                    connection_time="00:00:00"
                fi
            fi
            
            # Format and display user info - Exactly like proven working code
            printf "${BLUE}│${YELLOW} %-13s ${WHITE}%-12s ${WHITE}%-5s/%-7s ${WHITE}%-13s ${BLUE}│${RESET}\n" \
                   "$user" "$status" "$total_connections" "$limit" "$connection_time"
            
        done < "$DATABASE"
        
        echo -e "${BLUE}└────────────────────────────────────────────────────────────┘${RESET}"
        
        # Summary - Simple and working
        echo ""
        echo -e "${YELLOW}Summary: ${WHITE}Total Users: ${GREEN}$total_users${WHITE} | Online: ${GREEN}$online_users${WHITE} | Offline: ${RED}$((total_users - online_users))${RESET}"
        echo ""
    }
    
    # Main real-time monitoring function
    echo -e "${GREEN}🚀 Starting Real-Time User Monitor...${RESET}"
    echo -e "${YELLOW}⚡ Auto-refresh every $REFRESH_INTERVAL seconds${RESET}"
    echo -e "${WHITE}💡 Press CTRL+C to return to menu${RESET}"
    echo ""
    sleep 2
    
    # Trap CTRL+C to exit gracefully
    trap 'echo -e "\n${YELLOW}📡 Real-time monitoring stopped${RESET}"; return 0' INT
    
    # Real-time monitoring loop
    while true; do
        # Clear screen and show header
        clear
        local current_time=$(date "+%Y-%m-%d %H:%M:%S")
        
        # Professional header with timestamp
        echo -e "${BLUE}┌────────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${BLUE}│${WHITE}              🔍 REAL-TIME USER MONITOR 🔍                   ${BLUE}│${RESET}"
        echo -e "${BLUE}│${WHITE}                  Last Update: $current_time             ${BLUE}│${RESET}"
        echo -e "${BLUE}├────────────────────────────────────────────────────────────┤${RESET}"
        echo -e "${BLUE}│${WHITE} User        Status   Online/Limit Time Connected Type  ${BLUE}│${RESET}"
        echo -e "${BLUE}├────────────────────────────────────────────────────────────┤${RESET}"
        
        # Display current data
        display_user_monitor
        
        # Show refresh info
        echo -e "${GREEN}🔄 Refreshing in $REFRESH_INTERVAL seconds... ${YELLOW}(Press CTRL+C to exit)${RESET}"
        
        # Wait for refresh interval
        sleep $REFRESH_INTERVAL
    done
}

uninstall_script() {
  echo ">> Uninstall MK Script Manager <<"
  read -p "Are you sure? [y/N]: " c
  [[ "$c" =~ ^[Yy]$ ]] || { echo "Canceled."; return; }
  echo "[*] Removing stunnel..."
  systemctl stop stunnel4 2>/dev/null
  apt-get remove -y stunnel4 >/dev/null 2>&1
  rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem /etc/stunnel/key.pem /etc/stunnel/cert.pem
  rm -f /etc/default/stunnel4
  echo "[*] Removing users..."
  while IFS=: read -r username limit; do
    id "$username" &>/dev/null && userdel -r "$username"
  done < "$USER_LIST_FILE"
  echo "[*] Cleaning files..."
  rm -f /usr/local/bin/menu
  rm -rf /etc/mk-script
  rm -f /etc/security/limits.d/mk-script-limits.conf
  echo "[+] Uninstalled."
  exit 0
}

while true; do
  print_menu
  read choice
  echo
  case "$choice" in
    1) create_user ;;
    2) delete_user ;;
    3) limit_user ;;
    4) configure_tunnel ;;
    5) show_online_users ;;
    6) show_network_traffic ;;
    7) show_user_report ;;
    8) change_user_password ;;
    9) uninstall_script ;;
    *) echo "Invalid option. Enter 1-9." ;;
  esac
  [[ "$choice" != "9" ]] && read -n1 -s -r -p "Press any key to return..." && echo
done
