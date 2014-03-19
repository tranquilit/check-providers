check-providers
===============

On a router with multiple providers and shorewall, monitor the providers and enable/disable them when one is failing.restart openvpn if running on the failing provider.


    check_providers.py --help
    
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
