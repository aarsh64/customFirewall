SERVER_IP="192.168.86.35" #the machine which will be work as firewall machine(Linux machine)
ATTACK="192.168.86.39"    #this is the ip address of the attacker's machine (CentOS)
META="192.168.86.40"    #this is the ip address of the normal user's machine (Windows Machine)

case $1 in 
start)
echo "Firewall Implementation starts...."
echo "The blocked IP will be : $ATTACK";
echo "The accessible IP will be : $META";

  #Flusing iptables before stating applying new rules.
    iptables --flush
    iptables -t mangle --flush
    

    #Adding a new chain called LOG 
    iptables -A INPUT   -j LOG --log-prefix "FIREWALL:INPUT "
    iptables -A FORWARD -j LOG --log-prefix "FIREWALL:FORWARD " # logs will be stored in "/var/log/kern.log" path.
    iptables -A OUTPUT  -j LOG --log-prefix "FIREWALL:OUTPUT "
  
    #Default polices.
    iptables --policy INPUT DROP
    iptables --policy OUTPUT ACCEPT
    iptables --policy FORWARD DROP

    #Accept packets to and from local interface
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

     #Accept the packets of already connected streams
     iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
     iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    
    #--------------------------------------------------------------------------
        iptables -A INPUT -s $ATTACK -j DROP
        iptables -A OUTPUT -d $ATTACK -j DROP
        iptables -A INPUT -i e -p tcp -s $ATTACK -d $SERVER_IP --dport 21 -j DROP 
    #--------------------------------------------------------------------------
        
        iptables -A INPUT -i ens33 -p tcp -s $META -d $SERVER_IP --dport 21 -j ACCEPT
    
    # #Allow ICMP to local network but block for others
     iptables -A INPUT -i ens33 -p icmp -s 192.168.86.0/24 -j ACCEPT
     iptables -A OUTPUT -o ens33 -p icmp -d 192.168.86.0/24 -j ACCEPT
     iptables -A INPUT -i ens33 -p icmp -j REJECT
    

    # #Block bad or private ip addresses
     iptables -A INPUT -i ens33 -s 0.0.0.0/8 -j LOG
     iptables -A INPUT -i ens33 -s 127.0.0.0/8 -j LOG
     iptables -A INPUT -i ens33 -s 10.0.0.0/8 -j LOG
     iptables -A INPUT -i ens33 -s 172.16.0.0/12 -j LOG
     iptables -A INPUT -i ens33 -s 224.0.0.0/3 -j LOG

     # Protection against port scanning 
     iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j REJECT

    # #Block flag based in Pre-routing
     iptables -t mangle -A PREROUTING -i lo -j ACCEPT
     iptables -t mangle -A PREROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT  #conntrack is used to check connections 
     iptables -t mangle -A PREROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT #new packets make request to the system will be logged.
     iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j LOG 
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j LOG # will only match packets with the SYN flag set, 
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j LOG  
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j LOG   # and the ACK, FIN and RST flags unset.
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j LOG
     iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG

    # #DDoS attack protection...here --connlimit will block the requests if there are more tham 20 tcp connections 
     iptables -A INPUT -p tcp -m connlimit --connlimit-above 20 -j REJECT --reject-with tcp-reset

    #SSH prevention from all the system.
    iptables -A INPUT -p tcp --dport 22 --source $META -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 --source $ATTACK -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j DROP

    #SSH brute-force protection 
    iptables -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --set
    iptables -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j LOG
;;  
stop)
echo "stop block"
   #Clear all the rules in iptables
    iptables --flush
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
;;
esac