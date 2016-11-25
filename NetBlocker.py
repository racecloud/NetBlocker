import MailLogScanner
import AbuseIPDB
import ipaddress
import FirewallManager
import configparser
import sys


config = None
suspiciousIPs = {}


def addressInNetwork(ip, net):
   ipaddr = ipaddress.ip_address(ip)
   network = ipaddress.ip_network(net)
   return ipaddr in network


def addressInWhiteList(ip, whiteList):
    for net in whiteList:
        if addressInNetwork(ip, net):
            return True
    return False


def main():
    # Read configuration
    config_file = 'config.ini'
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    config = configparser.ConfigParser()
    print ("Reading config file {0}".format(config_file))
    config.read(config_file)

    # defines how many days an ip address should stay in firewall before re-checking against public databases
    JailTime = config.getint('general', 'JailTime')
    # number of attempts before we even consider blocking this IP
    NumberOfAttemptsAllowed = config.getint('general', 'NumberOfAttemptsAllowed')
    # number of attempts when we don't care if AbuseIPDB doesn't list it
    NumberOfAttemptsForceBlock = config.getint('general', 'NumberOfAttemptsForceBlock')

    tmp = config.get('general', 'whitelist')
    WhiteListNetworks = []
    if tmp:
        WhiteListNetworks = str.split(tmp)

    # Stage 1: Gather list of abuse IPs
    print('Read logs from srv1')
    srv1MailScanner = MailLogScanner.MailLogScanner('srv1')
    srv1MailIPs = srv1MailScanner.getSuspiciousIPs()

    # Stage 2: Setup connection to mikrotik router, get list of already marked as abusive IPs
    firewall = FirewallManager.FirewallManager(config)
    previouslyBlockedIPs = firewall.getBlockedIPs()

    # Stage 3: Prepare some other stuff like the connection to the AbuseIPDB
    abipdb = AbuseIPDB.AbuseIPDB(config.get('AbuseIPDB', 'key'))

    # Stage 4: Scan the abusive IPs,
    # - check if they already are firewalled, if yes - update timestamp; if no - check with abuseIPDB
    print('Scan list of suspicios addresses')
    for ip in srv1MailIPs:
        numberOfAttempts = srv1MailIPs[ip]
        if addressInWhiteList(ip, WhiteListNetworks):
            print ('Ignore ' + ip + ': in whitelist network (' + str(numberOfAttempts) + ' attempts)')
            continue
        # print('IP ' + ip + ' seen ' + str(srv1MailIPs[ip]) + ' times ')
        if numberOfAttempts > NumberOfAttemptsAllowed:
            # Check if already blocked
            if firewall.isIPBlocked(ip):
                print('Ignore ' + ip + ': already blocked (' + str(numberOfAttempts) + ' attempts)')
                continue

            if abipdb.isIPReported(ip, days=JailTime):
                print('Block ' + ip + ': AbuseIPDB says it must be blocked (' + str(numberOfAttempts) + ' attempts)')
                firewall.blockIP(ip)
            else:
                if numberOfAttempts > NumberOfAttemptsForceBlock:
                    print('Block ' + ip + ': AbuseIPDB doesn\'t list it, but number of attempts '
                                          '(' + str(numberOfAttempts) + ') is above force threshold')
                    firewall.blockIP(ip)
                else:
                    print('Ignore ' + ip + ': AbuseIPDB doesn\'t list it and attempts (' + str(numberOfAttempts) +
                          ') below force threshold')
        else:
            print('Ignore ' + ip + ': not enough attempts (' + str(numberOfAttempts) + ')')

    # Stage 5: check entries that are very old in our firewall if we should restore them
    expiredIPs = firewall.getIPsOlderThan(JailTime * 24 * 60 * 60)
    print('Check already-blocked ips (' + str(len(expiredIPs)) + ')')
    for ip in expiredIPs:
        # print('Re-check expired address ' + ip)
        if abipdb.isIPReported(ip, days=JailTime):
            print('KeepBlocked ' + ip + ': AbuseIPDB says this IP should still be blocked')
            firewall.updateBlockedIPDate(ip)
        else:
            print('UnBlock ' + ip + ': AbuseIPDB says this IP can be safely removed from firewall')
            firewall.unblockIP(ip)
    print('All done. Good bye!')


if __name__ == '__main__':
    main()