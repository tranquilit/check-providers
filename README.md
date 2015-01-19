check-providers
===============

On a router with multiple providers and shorewall, monitor the providers and enable/disable them when one is failing.restart openvpn if running on the failing provider.

It needs 2 test public IP not used for other services to be able to test provider reachability when provider is disabled (so without routing table) in shorewall.

Basically, it checks every <CHECK_INTERVAL> each provider sequentially. It sends pings and read rtt and loss. If loss or rtt is too high, the provider is declared unavailable.

When all providers have been checked, if there is at least one available provider, it disables the unavailable ones to make sure no connection use them.

Features
--------
* OpenVPN is restarted if it is found running on an unavailable provider, or if state of openvpn_master provider changed
* Status Leds on Alix box can be up or down depending on status of provider
* Check of providers can be triggered by running ''check_providers.py trigger'', interesting to put in ifup.d or ifdown.d, or ipup.d and ipdown.d handlers
* removes default gw in main routing table that could be put by dhcp clients
* adds static routes in main routing table for testing availibility without providers's own routing table

Technical details
-----------------
* default configuration file in /etc/check-providers.ini
* pid file in /var/run/check-providers.pid
* log file in /var/log/check-providers.log
* sending a -HUP signal to process triggers immediate provider check
* periodic providers check (every 60s by default) 


```check_providers.py --help```
    
    Usage: check_providers.py -c configfile action
    
    Check reachability of multiple providers managed by Shorewall
    enable or disable the providers based on maximum packets loss or RTT
    
    action is either :
      monitor : monitor in background all providers and enable/disable them
      check [all,<provider>] : check all or one provider and display reachability
      check-json [all,<provider>] : check providers and output state as json data
    
    
    Options:
      --version             show program's version number and exit
      -h, --help            show this help message and exit
      -i CHECK_INTERVAL, --check-interval=CHECK_INTERVAL
                            Config file full path (default: 60)
      -p PING_COUNT, --ping-count=PING_COUNT
                            Override ping count (default: 0)
      -c CONFIG, --config=CONFIG
                            Config file full path (default: /etc/check-
                            providers.ini)
      -d, --dry-run         Dry run (default: False)
      -v, --verbose         More information (default: False)
      -o LOGFILE, --log=LOGFILE
                            Path to log file (default: none)
      -l LOGLEVEL, --loglevel=LOGLEVEL
                            Loglevel (default: info)

## Example config file

```vi /etc/check-providers.ini```

    [ADSL]
    device=eth0
    target_ip=185.16.67.23
    gateway=192.168.1.1
    led=2
    openvpn_master=1
    
    [GSM]
    device=ppp3g
    target_ip=185.16.67.24
    max_loss=40
    max_rtt=2000
    ping_count=20
    timeout=3
    led=3
    fallback=1
    
## Ini file options

One section for each provider, named the same as in the shorewall **http://shorewall.net/manpages/shorewall-providers.html** file

|Parameters      |  Value             | Descriptions  |
|----------------|--------------------|---------------|
|target_ip       | 1.2.3.4            | IP to ping to test availability |
|device          | eth?, ppp?         | local device on which provider is connected |
|gateway         | 1.2.3.4            | next hop to test ARP ping                   |
|max_rtt         | 2000               | max round trip time in ms to accept provider|
|timeout         | 3                  | timout is sec for the ping                  |
|ping_interval   | 0.4                | interval between ping                       |
|max_loss        | 30                 | max % of lost packets to accept provider    |
|ping_count      | 4                  | count of ping                               |
|led             | 1,2,3              | on Alix router, power on/off led depending of availability | 
|openvpn_master  | 0,1                | is provider used by openvpn (openvpn is restarted if vpn is running on provider)|
|fallback        | 0,1                | is provider a fallback provider, in this case, it is never disabled. |
|source_ip       | 1.2.3.4            | optional source_ip fo rthe provider in cas the providers are sharing the same physical interface |


Typical setup on debian wheezy
==============================

* install a shorewall in multi-provider mode
* For provider in NAT mode (provider eth device has a non routable ip), don't declare a gateway, add rule to put led blinking and trigger providers availability 

````vi /etc/network/interfaces````


````
# The primary network interface
auto eth0
iface eth0 inet static
        address 192.168.1.11
        netmask 255.255.255.0
        up echo timer > /sys/class/leds/alix\:2/trigger
        up /usr/bin/python /usr/local/bin/check_providers.py trigger
        down echo 0 > /sys/class/leds/alix\:2/brightness
        down /usr/bin/python /usr/local/bin/check_providers.py trigger
````

* for provider in pppoe mode

````vi /etc/network/interfaces````


````
auto ppp0
iface ppp0 inet ppp
    provider dslprovider
    # led blinks during session setup
    up echo timer > /sys/class/leds/alix\:3/trigger
    down echo 0 > /sys/class/leds/alix\:3/brightness
````

in /etc/ppp/ip-up.d/ppp-status :
````
DEVICE=$1
MODEM=$2
SPEED=$3
IP=$4
PPP_IP=$5

# allume la led et active le provider GSM immediatement
if [ $DEVICE = "ppp0" ]; then
  led=3
  /sbin/shorewall enable GSM
  check_providers.py trigger
  # power on / off leds on Alix
  echo none > /sys/class/leds/alix\:$led/trigger
 echo 1 > /sys/class/leds/alix\:$led/brightness
fi

exit 0

````

same for down

````
#!/bin/sh
DEVICE=$1
MODEM=$2
SPEED=$3
IP=$4
PPP_IP=$5

# eteindre la led 3 pour gsm et la 2 pour le reste (arbitrairement...)
if [ $DEVICE = "ppp0" ]; then
  led=3
  /sbin/shorewall disable GSM
  # power on / off leds on Alix
  echo none > /sys/class/leds/alix\:$led/trigger
  echo 0 > /sys/class/leds/alix\:$led/brightness
fi


exit 0
````
