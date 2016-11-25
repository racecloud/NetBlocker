# NetBlocker
Specific implementation of a firewall script that parses logs from various servers, checks addresses against public databases with offensive hosts and adjusts a MikroTik firewall.

# !!!WARNING!!!
This is something I implement for my personal use and mostly out of curiosity for Python programming. There are many great tools out there which will work way better! Use at your own risk

## Target Features (not all implemented yet):
 * Aggregation of offensive hosts - parse mail logs and http access logs from multiple servers, based on simple regular expressions. Simple logic to choose which of the suspected addresses should be considered for blocking
 * Validation against AbuseIPDB and RBLs
 * Integration with MikroTik API to keep a list of addresses updated in the firewall
 
## Requirements
 * Python 3 (I use 3.5. probably will work with any 3.x)
 * Non-standard python packages (install with `pip install`): `dnspython`, `paramiko`, `requests`
 * The machine that runs the scripts must have ssh access to the servers using rsa keys, support for user/password authentication not yet implemented
 * Access to the MikroTik with username/password. Also make sure the API is enabled
 
## Usage
Create a config.ini file (check the sample provided) and run the NetBlocker.py. Make sure to setup the appropriate drop rules on your Mikrotik Firewall, something like this:
~~~~
/ip firewall filter
add action=drop chain=forward src-address-list="Complete Block"
add action=drop chain=input src-address-list="Complete Block"
~~~~
 
## TODO
- [ ] Currently the algorithm just counts number of occurrences of IPs in a log file. Must add support for weights depending on what was in the file
- [ ] Add support for regular expressions matching in the logs (currently we just search a string)
- [ ] Add support for configuring the list of RBL domains we check against
- [ ] Add support for apache access logs (maybe ssh and etc)
- [ ] Add pid file check so when using cron job we don't have overlaps
- [ ] Configurable logging
- [ ] At the moment error handling is minimal at best
- [ ] Add option to configure the name of the address list we manage on the router
