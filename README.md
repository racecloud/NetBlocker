# NetBlocker
Specific implementation of a firewall script that parses logs from various servers, checks addresses against public databases with offensive hosts and adjusts a MikroTik firewall.

# !!!WARNING!!!
This is something I implement for my personal use and mostly out of curiosity for Python programming. There are many great tools out there which will work way better! Use at your own risk

## Target Features (not all implemented yet):
 * Aggregation of offensive hosts - parse mail logs and http access logs from multiple servers, based on simple regular expressions. Simple logic to choose which of the suspected addresses should be considered for blocking
 * Validation against AbuseIPDB and zen.spamhaus
 * Integration with MikroTik API to keep a list of addresses updated in the firewall
 
## Requirements
 * Python 3 (I use 3.5. probably will work with any 3.x)
 * Non-standard python packages (install with `pip install`): `dnspython`, `paramiko`, `requests`
 * The machine that runs the scripts must have ssh access to the servers using rsa keys, support for user/password authentication not implemented
 * Access to the MikroTik is with username/password. Also make sure the API is enabled
 
## TODO
- [ ] List of hosts is not configurable yet
- [ ] Add the intended support for zen.spamhaus
- [ ] Add support for apache access logs (maybe ssh and etc)
- [ ] Add pid file check so when using cron job we don't have overlaps
- [ ] Configurable logging, exception handling, etc
