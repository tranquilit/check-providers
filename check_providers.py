#! /usr/bin/python
# -*- coding: UTF-8 -*-
#-------------------------------------------------------------------------------
# Name: check_providers.py
# Purpose: enable/disable shoewall providers based on ICMP reachability
# update openvpn configuration
# Author: htouvet
#
# Created: 03/03/2014
# Copyright: (c) htouvet 2014
# Licence: GPL V2
#-------------------------------------------------------------------------------

import os
import sys
import subprocess
import logging
import re
import time
import datetime

import json

import signal

from iniparse import RawConfigParser
from optparse import OptionParser
from distutils.spawn import find_executable

usage="""\
%prog -c configfile action

Check reachability of multiple providers managed by Shorewall
enable or disable the providers based on maximum packets loss or RTT

action is either :
monitor : monitor in background all providers and enable/disable them
check [all,<provider>] : check all or one provider and display reachability
check-json [all,<provider>] : check providers and output state as json data
"""

version = "0.0.1"

parser=OptionParser(usage=usage,version="%prog " + version)
parser.add_option("-i","--check-interval", dest="check_interval", type=int, default=60, help="Config file full path (default: %default)")
parser.add_option("-p","--ping-count", dest="ping_count", type=int, default=0, help="Override ping count (default: %default)")
parser.add_option("-c","--config", dest="config", default='/etc/check-providers.ini', help="Config file full path (default: %default)")
parser.add_option("-d","--dry-run", dest="dry_run", default=False, action='store_true', help="Dry run (default: %default)")
parser.add_option("-v","--verbose", dest="verbose", default=False, action='store_true', help="More information (default: %default)")
parser.add_option("-o","--log", dest="logfile", default=None, help="Path to log file (default: %default)")
parser.add_option("-l","--loglevel", dest="loglevel", default='info', type='choice', choices=['debug','warning','info','error','critical'], metavar='LOGLEVEL',help="Loglevel (default: %default)")

REPORT = re.compile(r'\n(?P<transmitted>\d+)\s+packets transmitted,\s+(?P<received>\d+) received,\s+(?P<loss>\d+)%\s+packet loss')
RTT = re.compile(r'rtt min/avg/max/mdev = (?P<min>[0-9.]+)/(?P<avg>[0-9.]+)/(?P<max>[0-9.]+)/(?P<mdev>[0-9.]+) ms')


def run(cmd,dry_run=False):
  try:
    logger.debug(' running {}'.format(cmd))
    if not dry_run:
      p = subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
      logger.debug(' output : {}'.format(p))
      return (0,p)
    else:
      print("DRYRUN : {}".format(cmd))
      return(0,"#### DRYRUN ### no output for {}".format(cmd))

  except subprocess.CalledProcessError as e:
    return (e.returncode,e.output)


def default_json(o):
  if hasattr(o,'as_dict'):
    return o.as_dict()
  elif hasattr(o,'as_json'):
    return o.as_json()
  elif isinstance(o,datetime.datetime):
    return o.isoformat()
  else:
    return u"{}".format(o)

def jsondumps(o,**kwargs):
  """extended json dump of o"""
  return json.dumps(o,default=default_json,**kwargs)

def arping(device,target_ip,ping_count=3):
  # arping
  #root@gw-pironniere:/opt/check-providers# arping -i eth0 -c4 192.168.149.254
  """\
ARPING 192.168.149.254
60 bytes from 00:0a:fa:24:18:f7 (192.168.149.254): index=0 time=229.674 usec
60 bytes from 00:0a:fa:24:18:f7 (192.168.149.254): index=1 time=258.173 usec
60 bytes from 00:0a:fa:24:18:f7 (192.168.149.254): index=2 time=251.468 usec
60 bytes from 00:0a:fa:24:18:f7 (192.168.149.254): index=3 time=252.305 usec

--- 192.168.149.254 statistics ---
4 packets transmitted, 4 packets received, 0% unanswered (0 extra)
"""
  # iputils-arping
  #root@gw-pironniere:/opt/check-providers# arping -c2 192.168.149.254
  """\
ARPING 192.168.149.254 from 192.168.149.184 eth0
Unicast reply from 192.168.149.254 [00:0A:FA:24:18:F7] 0.886ms
Unicast reply from 192.168.149.254 [00:0A:FA:24:18:F7] 0.777ms
Sent 2 probes (1 broadcast(s))
"""
  ARPING1 = re.compile(r'bytes from (?P<mac>\S+).*time=(?P<rtt>[0-9.]*) (?P<unit>.*)')
  ARPING2 = re.compile(r'reply from.*\[(?P<mac>\S+)\]\s+(?P<rtt>[0-9.]*)(?P<unit>.*)')
  ARPING_PATH = find_executable('arping')
  if ARPING_PATH == None:
    raise Exception('No arping command found')
  elif "/usr/bin/arping" in ARPING_PATH:
    (returncode,output) = run('arping -c{ping_count} -I{device} {target_ip}'.format(
      ping_count = ping_count,
      device = device,
      target_ip = target_ip,
    ))
    packets = [p.groupdict() for p in ARPING2.finditer(output)]
  elif "/usr/sbin/arping" in ARPING_PATH:
    (returncode,output) = run('arping -c{ping_count} -i{device} {target_ip}'.format(
      ping_count = ping_count,
      device = device,
      target_ip = target_ip,
    ))
    packets = [p.groupdict() for p in ARPING1.finditer(output)]
  result = {}
  if packets:
    result['mac'] = packets[-1]['mac']
    result['rtt'] = packets[-1]['rtt']+packets[-1]['unit']
    result['alive'] = len(packets)>0
  else:
    result['mac'] = None
    result['rtt'] = None
    result['alive'] = False
  return result

class Provider(object):
  def __init__(self,provider_name,device=None,gateway=None,target_ip=None,max_rtt=2000.0,max_loss=30,ping_count=10,ping_interval=0.5,timeout=1.5,led=None):
    """Parameters of an Internet provider as defined in Shorewall and availability limits
"""
    self.target_ip=target_ip
    self.provider_name=provider_name
    self.device=device
    self.device_type=None
    self.device_mac=None
    self.last_ip=None

    self._gateway=gateway

    self.gateway_alive = None
    self.gateway_rtt = None
    self.gateway_mac = None

    self.max_rtt=max_rtt
    self.max_loss=max_loss
    self.ping_count = ping_count
    self.ping_interval = ping_interval
    self.timeout = timeout

    self.openvpn_master = 0
    self.fallback = 0

    self.last_rtt = None
    self.last_loss = None

    self._available = None
    self._link_states = []
    self._link_status = 'UNKNOWN'

    self.led = led
    self.status = ''
    self.last_check_time = None
    self.last_enabled = None

    self.dry_run = False

  def used_by_openvpn(self,proto='udp',port=1194):
    (retcode,output) = run('conntrack -L -p {proto} --dport {port} -o extended | grep "={src}"'.format(proto=proto,src=self.last_ip,port=port))
    """
conntrack v1.2.1 (conntrack-tools): 1 flow entries have been shown.
ipv4 2 udp 17 178 src=192.168.149.184 dst=80.13.55.10 sport=1194 dport=1194 src=80.13.55.10 dst=192.168.149.184 sport=1194 dport=1194 [ASSURED] mark=1 use=1
"""
    conn = output.splitlines()
    for c in conn:
        if "={src} ".format(src=self.last_ip) in c:
            return True
    return False

  def openvpn_local_sockets(self):
    """
    Returns:
        list of str of IP where openvpn is bound.
    """
    (retcode,output) = run("/bin/netstat -lupnw | grep -E '(udp|tcp) .*/openvpn'")
    """
    udp        0      0 192.168.1.254:1194      0.0.0.0:*                           16919/openvpn
    """
    result = []
    listening = output.splitlines()
    for conn in listening:
        args = conn.split()
        proto = args[0]
        (local_ip,local_port) = args[3].rsplit(':',1)
        result.append((proto,local_ip,local_port))

  def delete_openvpn_conntrack(self):
    """Remove conntrack entries matching the OpenVPN listening processes"""
    for (proto,ip,port) in self.openvpn_local_sockets():
        if ip != '0.0.0.0':
            run('/usr/sbin/conntrack -D -p {proto} -s {src} --sport={port}'.format(src=ip,proto=proto,port=port),dry_run=self.dry_run)

  def read_config(self,config_file):
    for attrib in ['target_ip','device','gateway']:
      if config_file.has_option(self.provider_name,attrib):
        if attrib == 'gateway':
          setattr(self,'_gateway',config_file.get(self.provider_name,attrib))
        else:
          setattr(self,attrib,config_file.get(self.provider_name,attrib))

    for attrib in ['max_rtt','timeout','ping_interval']:
      if config_file.has_option(self.provider_name,attrib):
        setattr(self,attrib,config_file.getfloat(self.provider_name,attrib))

    for attrib in ['max_loss','ping_count','led','openvpn_master','fallback']:
      if config_file.has_option(self.provider_name,attrib):
        setattr(self,attrib,config_file.getint(self.provider_name,attrib))

  @property
  def device_up(self):
    (retcode,output) = run('ip link show dev {device}'.format(device=self.device))
    """
4: eth2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast master br1 state DOWN mode DEFAULT qlen 1000
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN mode DEFAULT qlen 1000
4: eth2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast master br1 state DOWN mode DEFAULT qlen 1000
10: ppp3g: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN mode DEFAULT qlen 3
6: br1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT
"""
    LINK = re.compile(r':\s+<(?P<link_states>.+)>.* state (?P<link_status>.+?)\s')
    link = LINK.search(output)
    if link:
      self._link_states = link.groupdict()['link_states'].split(',')
      self._link_status = link.groupdict()['link_status']
      return (self._link_status == 'UP') or ('LOWER_UP' in self._link_states)
    else:
      return None

  def check_test_route(self):
    """Test if there is a route to target_ip through the gateway or interface, and add it if not present"""
    if self.target_ip:
      (retcode,route) = run('/sbin/ip route show {target_ip}'.format(target_ip=self.target_ip))
      if self.gateway:
        if not "{target_ip} via {gateway}".format(target_ip=self.target_ip,gateway=self.gateway) in route:
          logger.debug(run('/sbin/ip route del {target_ip}'.format(target_ip=self.target_ip),dry_run=self.dry_run)[1])
          logger.warning('No route for {target_ip} via {gateway}, adding one'.format(target_ip=self.target_ip,gateway=self.gateway))
          logger.debug(run('/sbin/ip route add {target_ip} via {gateway}'.format(target_ip=self.target_ip,gateway=self.gateway),dry_run=self.dry_run)[1])
      elif self.device:
        if not " {} ".format(self.device) in route:
          logger.warning('No route for {target_ip} through {device}, adding one'.format(target_ip=self.target_ip,device=self.device))
          logger.debug(run('/sbin/ip route add {target_ip} dev {device}'.format(target_ip=self.target_ip,device=self.device),dry_run=self.dry_run)[1])
      else:
        logger.critical('No gateway for {target_ip}'.format(target_ip=self.target_ip))

  def check_gateway(self):
    if self.gateway:
      result = arping(device=self.device,target_ip=self.gateway)
      self.gateway_mac = result['mac']
      self.gateway_rtt = result['rtt']
      self.gateway_alive = result['alive']
    else:
      self.gateway_mac = None
      self.gateway_rtt = None
      self.gateway_alive = None
    return self.gateway_alive

  def check_available(self):
    """ping the target and change available property based on max_rtt and max_loss
available == True if actual rtt and loss are below the max_rtt and max_loss
"""
    self._available = None
    self.last_check_time = datetime.datetime.now()
    if self.device_up:
      self.check_local_ip()
      if self.gateway and not self.check_gateway():
        self.status = 'Gateway {} not reachable'.format(self.gateway)
        logger.critical('Gateway {} not reachable'.format(self.gateway))
      ping_ip = self.target_ip
      if ping_ip:
        self.check_test_route()
        (returncode,output) = run('/bin/ping -q -n -c{ping_count:n} -W{timeout:n} -i{ping_interval} -I{device} {target_ip}'.format(
          ping_count = self.ping_count,
          timeout = self.timeout,
          device = self.device,
          target_ip = ping_ip,
          ping_interval=self.ping_interval,
        ))
        if returncode == 0:
          report = REPORT.search(output)
          rtt = RTT.search(output)
          if report:
            self.last_loss = int(report.groupdict()['loss'])
          else:
            self.last_loss = None
          if rtt:
            self.last_rtt = float(rtt.groupdict()['avg'])
          else:
            self.last_rtt = None

          self._available = report and rtt and\
            self.last_loss<=self.max_loss and\
            self.last_rtt<=self.max_rtt
          if self._available:
            self.status='OK'
          elif self.last_loss>self.max_loss:
            self.status='Too much loss {}%'.format(self.last_loss)
          elif self.last_rtt>self.max_rtt:
            self.status='Too long RTT {}ms'.format(self.last_rtt)
        else:
          self.status = 'ping test failed : {}'.format(output)
      else:
        self._available = True
    else:
      self.status = 'Device {} is down or link state is unknown'.format(self.device)
      self._available = False

    self.update_leds()
    return self._available

  def check_local_ip(self):
    """Get local ip of device, set ip, device_mac and device_type"""
    (retcode,output) = run('ip addr show dev {device}'.format(device=self.device))
    IPV4ADDR = re.compile(r'\sinet\s+(?P<ipv4>\d+.\d+.\d+.\d+)[/\s]')
    MACADDR = re.compile(r'link/(?P<type>\S+)(\s(?P<mac>\S+))?')
    ipaddr = IPV4ADDR.search(output)
    if ipaddr:
      self.last_ip = ipaddr.groupdict()['ipv4']
    else:
      self.last_ip = None
    macaddr = MACADDR.search(output)
    if macaddr:
      self.device_mac = macaddr.groupdict()['mac']
      self.device_type = macaddr.groupdict()['type']
    else:
      self.device_mac = None
      self.device_type = None
    return self.last_ip

  @property
  def gateway(self):
    if self._gateway:
      #ppp, shorewall notation for no gateway
      if self._gateway == '-':
        return None
      else:
        return self._gateway
    else:
      #from dhcp
      (retcode,output) = run('ip route list table {}'.format(self.provider_name))
      """root@htouv:~# ip route list dev eth1
88.163.76.0/24 proto kernel scope link src 88.163.76.120
88.163.76.254 scope link src 88.163.76.120
"""
      GW = re.compile(r'default via (?P<gateway>\d+.\d+.\d+.\d+)\s+')
      gw = GW.search(output)
      if gw:
        logger.debug('Gateway : {}'.format(gw.groupdict()['gateway']))
        return gw.groupdict()['gateway']
      else:
        logger.debug('No gateway')
        return None

  @gateway.setter
  def gateway_set(self,value):
    self._gateway = value

  @property
  def enabled(self):
    try:
      (retcode,routes) = run('ip route list table {}'.format(self.provider_name))
      if retcode == 0:
        routes = routes.splitlines()
        self.last_enabled = len(routes)>0
      else:
        self.last_enabled = False
      return self.last_enabled
    except Exception as e:
      logger.critical("Unable to get enabled status from routing table: {}".format(e))
      return self.last_enabled

  def led_off(self):
    led_path = '/sys/class/leds/alix:{}'.format(self.led)
    if os.path.isdir(led_path):
      with open(os.path.join(led_path,'brightness'),'wb') as f:
        f.write('0')
      with open(os.path.join(led_path,'trigger'),'wb') as f:
        f.write('none')

  def led_on(self):
    led_path = '/sys/class/leds/alix:{}'.format(self.led)
    if os.path.isdir(led_path):
      with open(os.path.join(led_path,'trigger'),'wb') as f:
        f.write('none')
      with open(os.path.join(led_path,'brightness'),'wb') as f:
        f.write('1')

  def led_blink(self):
    led_path = '/sys/class/leds/alix:{}'.format(self.led)
    if os.path.isdir(led_path):
      with open(os.path.join(led_path,'brightness'),'wb') as f:
        f.write('1')
      with open(os.path.join(led_path,'trigger'),'wb') as f:
        f.write('timer')

  def update_leds(self):
    """"""
    # /sys/class/leds/alix\:1/trigger
    #none backlight default-on [heartbeat] timer
    if self.enabled:
      if self._available:
        self.led_on()
      elif self.device_up:
        self.led_blink()
      else:
        self.led_off()
    else:
      self.led_off()

  def enable(self):
    if not self.enabled:
      logger.debug('Enable {}'.format(self.provider_name))
      try:
          print(run('/var/lib/shorewall/firewall enable {}'.format(self.provider_name),dry_run=self.dry_run))
      except Exception as e:
          logger.info('Retrying to disable/enable provider because %s'% e)
          print(run('/var/lib/shorewall/firewall restart',dry_run=self.dry_run))
      if self.openvpn_master:
        logger.info('Restarting openvpn')
        print(run('/etc/init.d/openvpn stop',dry_run=self.dry_run))
        print(run('ip route flush cache',dry_run=self.dry_run))
        self.delete_openvpn_conntrack()
        print(run('/etc/init.d/openvpn start',dry_run=self.dry_run))
      # here check the connectivity.... else rollback
      self.update_leds()
      print('Routes after enabling provider %s\n%s'%(self.provider_name,run('/sbin/shorewall show routing')))
    else:
      logger.debug('{} already enabled'.format(self.device))

  def disable(self):
    if self.enabled:
      openvpn = self.used_by_openvpn()
      logger.debug('Disable {}'.format(self.provider_name))
      # restart openvpn if it was running on this provider
      if openvpn:
        logger.info('openvpn was running here, stopping openvpn')
        print(run('/etc/init.d/openvpn stop',dry_run=self.dry_run))
      print(run('/var/lib/shorewall/firewall disable {}'.format(self.provider_name),dry_run=self.dry_run))
      # remove connections
      if self.last_ip:
        logger.info('removing conntrack entries')
        logger.info(run('/usr/sbin/conntrack -D -s {src}'.format(src=self.last_ip),dry_run=self.dry_run)[1])
        logger.info(run('/usr/sbin/conntrack -D -q {src}'.format(src=self.last_ip),dry_run=self.dry_run)[1])
      # be sure there is no default gw in main table so that fallback provider can be reached
      self.remove_default_gw()
      # restart openvpn if it was running on this provider
      if openvpn:
        logger.info('openvpn was running here, restarting openvpn')
        print(run('/etc/init.d/openvpn start',dry_run=self.dry_run))
      self.update_leds()
      print('Routes after provider %s disabling\n%s'%(self.provider_name,run('/sbin/shorewall show routing')))

  def remove_default_gw(self):
    """Remove default route which could have been added in main routing table and will prevent fallback interface from taking over"""
    (retcode,routes) = run('ip route list table main dev {}'.format(self.device))
    if retcode == 0:
      if 'default ' in routes:
        print(run('ip route del default table main dev {}'.format(self.device),dry_run=self.dry_run))

  def __str__(self):
    def get_available(en):
      if en is None:
        return "UNKNOWN"
      elif en:
        return "AVAILABLE"
      else:
        return "UNUSABLE"

    return "Provider {provider} on {device} ip:{local_ip} nh:{gw} (testing IP:{target_ip}) loss:{loss}%,rtt:{rtt}ms {available} ({status})".format(
      available=get_available(self._available),
      provider=self.provider_name,
      device=self.device,
      target_ip=self.target_ip,
      loss = self.last_loss,
      rtt = self.last_rtt,
      local_ip = self.last_ip,
      gw = self.gateway or "-",
      status = self.status,
    )

  def as_dict(self):
    return dict(
      target_ip = self.target_ip,
      provider_name = self.provider_name,
      device = self.device,
      gateway = self._gateway,
      max_rtt = self.max_rtt,
      max_loss = self.max_loss,
      ping_count = self.ping_count,
      ping_interval = self.ping_interval,
      ping_timeout = self.timeout,
      last_rtt = self.last_rtt,
      last_loss = self.last_loss,
      available = self._available,
      link_states = self._link_states,
      link_status = self._link_status,
      led = self.led,
      status = self.status,
      last_check_time = self.last_check_time,
      last_ip = self.last_ip,
      device_mac = self.device_mac,
      device_type = self.device_type,
      gateway_alive = self.gateway_alive,
      gateway_mac = self.gateway_mac,
      gateway_rtt = self.gateway_rtt,
      enabled = self.last_enabled,
    )

def read_config(filename,providers):
  cp = RawConfigParser()
  cp.read(filename)

  while providers:
    providers.pop()

  for provider_name in cp.sections():
    provider = Provider(provider_name)
    provider.read_config(cp)
    providers.append(provider)

def is_pid_running(pidfile):
  """return pid if pid in pidfile is a running process, remove pidfile if pid is no more running"""
  if os.path.isfile(pidfile):
    with open(pidfile,'rb') as f:
      pid = f.read().strip()
    if pid and os.path.isdir("/proc/{}".format(pid)):
      return int(pid)
    else:
      os.unlink(pidfile)
      return None
  else:
    return None


def write_pidfile(pidfile,pid=None):
  if pid is None:
    pid = os.getpid()
  oldpid = is_pid_running(pidfile)
  if oldpid:
    if oldpid <> pid:
      raise Exception('There is already a running process {} for the pid file {}'.format(oldpid,pidfile))

  with open(pidfile,"wb") as f:
    f.write(str(pid))

def remove_pidfile(pidfile):
  if os.path.isfile(pidfile):
    os.unlink(pidfile)

if __name__ == '__main__':
  (options,args)=parser.parse_args()

  if len(args) < 1:
    print "ERROR : You must provide one action to perform"
    parser.print_usage()
    sys.exit(2)

  action = args[0]
  config_file =options.config
  dry_run = options.dry_run
  verbose = options.verbose
  loglevel = options.loglevel

  monitor_pid_file = '/var/run/check-providers.pid'
  current_pid = os.getpid()

  # setup Logger
  logger = logging.getLogger()
  if options.logfile:
    hdlr = logging.FileHandler(filename=options.logfile,encoding='utf8')
    hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(hdlr)
  else:
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

  # set loglevel
  if loglevel in ('debug','warning','info','error','critical'):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
      raise ValueError('Invalid log level: %s' % loglevel)
    logger.setLevel(numeric_level)

  # Config file
  if not os.path.isfile(config_file):
    logger.error("Error : could not find file : " + config_file + ", please check the path")
  logger.debug("Using " + config_file + " config file")

  #adsl = Provider('ADSL',device='eth0',target_ip='185.16.48.54',gateway='192.168.149.254')
  #gsm = Provider('GSM',device='ppp3g',target_ip='185.16.48.55',max_loss=40,max_rtt=2000,ping_count=20)

  providers = []
  read_config(config_file,providers)

  if options.ping_count:
    for provider in providers:
      provider.ping_count = options.ping_count

  if options.dry_run:
    logger.warning('### DRY RUN ### no change to routing or interface state will be performed')
    for provider in providers:
      provider.dry_run = options.dry_run

  if action == 'stop':
    monitor_pid = is_pid_running(monitor_pid_file)
    if monitor_pid:
      # wakeup current monitor...
      logger.info('Sending a TERM signal to running monitor process {}'.format(monitor_pid))
      os.kill(monitor_pid,signal.SIGTERM)
      sys.exit(0)
    else:
      logger.warning('No running monitoring found')
      sys.exit(0)

  if action == 'trigger':
    monitor_pid = is_pid_running(monitor_pid_file)
    if monitor_pid:
      # wakeup current monitor...
      logger.info('Sending a wakeup signal to running monitor process {}'.format(monitor_pid))
      os.kill(monitor_pid,signal.SIGHUP)
      sys.exit(0)
    else:
      logger.critical('No running monitoring found')
      sys.exit(1)

  if action == 'monitor':
    monitor_pid = is_pid_running(monitor_pid_file)
    if monitor_pid:
      # wakeup current monitor...
      logger.info('Sending a wakeup signal to running monitor process {}'.format(monitor_pid))
      os.kill(monitor_pid,signal.SIGHUP)
      sys.exit(0)
    else:
      try:
        write_pidfile(monitor_pid_file)

        def handler(signum,frame):
          global providers
          logger.info('Wake up by signal {}'.format(signum))
          if signum == signal.SIGHUP:
            logger.info(jsondumps(providers,indent=True))
          elif signum == signal.SIGTERM:
            logger.info('Received kill, closing')
            remove_pidfile(monitor_pid_file)
            sys.exit(0)

        # Set the signal handler and a alarm
        signal.signal(signal.SIGALRM, handler)
        signal.signal(signal.SIGHUP, handler)
        signal.signal(signal.SIGTERM, handler)

        while True:
          try:
            logger.info('Checking providers {}:'.format(','.join([provider.provider_name for provider in providers])))
            current_ok = [ provider for provider in providers if provider.check_available() ]
            # list of providers which are used by openvpn
            openvpn_prov = [ provider for provider in providers if provider.used_by_openvpn() ]
            shorewall_restart_needed = False
            for provider in providers:
              # we will check if a workable provider needs to be enabled by shorewall
              if provider._available:
                if not provider.enabled:
                  logger.warning("Enabling the available provider {}".format(provider.provider_name))
                  provider.enable()
                # todo : check balance routing table. If an interface involved in default route is removed (ppp or tun)
                #    the entire default route entry is removed by the kernel.
                # so if we can't find a route which refer to it in balance table, trigger a restart of shorewall to cleanup the situation...
                if not shorewall_restart_needed and not provider.fallback:
                    (retcode,output) = run('ip route show table balance')
                    """
                    default
                        nexthop via 185.16.51.9  realm 3 dev eth1 weight 1
                        nexthop dev tun2 weight 1
                    """
                    balance = output.splitlines()
                    in_balance = False
                    for l in balance:
                        if provider.gateway in l.split(' ') or provider.device in l.split(' '):
                            in_balance= True
                            break
                    if not in_balance:
                        shorewall_restart_needed = True
                        logger.critical("Shorewall restart needed because provider {} is not in default balance route ".format(provider.provider_name))

              else:
                if provider.enabled:
                  if current_ok and not provider.fallback:
                    logger.critical("Disabling the provider {} because {}".format(provider.provider_name,provider.status))
                    provider.disable()
                  else:
                    if not current_ok:
                      logger.critical("About to disable provider {} but will not because there are no other one".format(provider.provider_name))
                    else:
                      logger.critical("Not disabling fallback provider {}".format(provider.provider_name))
              logger.info(' {}'.format(provider))



            signal.alarm(options.check_interval)
            signal.pause()
            #time.sleep(options.check_interval)
          except Exception as e:
            logger.critical(e)
            #raise
      finally:
        remove_pidfile(monitor_pid_file)

  elif action == 'check':
    if len(args) >= 2:
      selproviders = [ provider for provider in providers if provider.provider_name in args[1:]]
    else:
      selproviders = providers
    for provider in selproviders:
      print "Checking {}".format(provider.provider_name)
      provider.check_available()
      print provider
      if provider.used_by_openvpn():
         print "This provider is used by Openvpn"
  elif action == 'check-json':
    result = []
    if len(args) >= 2:
      selproviders = [ provider for provider in providers if provider.provider_name in args[1:]]
    else:
      selproviders = providers
    for provider in selproviders:
      provider.check_available()
      result.append(provider.as_dict())
    print jsondumps(result,indent=True)
