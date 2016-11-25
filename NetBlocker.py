from nb import FirewallManager, MikrotikApi
from nb.public_dbs import PublicDBs
from nb.scanners import MailLogScanner
import ipaddress
import configparser
import sys


def address_in_network(ip, net):
    ip = ipaddress.ip_address(ip)
    network = ipaddress.ip_network(net)
    return ip in network


def address_in_whitelist(ip, whitelist):
    for net in whitelist:
        if address_in_network(ip, net):
            return True
    return False


def main():
    # ------------
    # Read configuration
    config_file = 'config.ini'
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    config = configparser.ConfigParser()
    print("Reading config file {0}".format(config_file))
    config.read(config_file)

    # defines how many days an ip address should stay in firewall before re-checking against public databases
    jail_time = config.getint('general', 'JailTime')
    # number of attempts before we even consider blocking this IP
    number_of_attempts_allowed = config.getint('general', 'NumberOfAttemptsAllowed')
    # number of attempts when we don't care if public dbs don't list it yet
    number_of_attempts_force_block = config.getint('general', 'NumberOfAttemptsForceBlock')

    tmp = config.get('general', 'whitelist')
    white_list_networks = []
    if tmp:
        white_list_networks = str.split(tmp)

    # ------------
    # Contact the servers, gather list of offensive IPs
    offensive_ips = {}
    config_sections = config.sections()
    for section_name in config_sections:
        if section_name == 'general':
            continue
        section_config = config[section_name]
        server_type = section_config.get('type')
        print('Reading ips from server ' + section_config.get('address') + ', type ' + server_type)
        if server_type == 'mail':
            scanner = MailLogScanner.MailLogScanner(section_config)
            new_ips = scanner.getSuspiciousIPs()
            # Note that the scanners give us a dictionary ip:weight so we have to combine and sum them
            offensive_ips = {k: offensive_ips.get(k, 0) + new_ips.get(k, 0) for k in set(offensive_ips) | set(new_ips)}

    # ------------
    # Setup connection to mikrotik router, prepare public databases access, etc
    firewall = FirewallManager.FirewallManager(config)
    public_dbs_checker = PublicDBs.PublicDBs(config)

    # ------------
    # The main algorithm - check the list of the addresses against the currently blocked and public databases and act
    print('Scan list of suspicious addresses')
    for ip in offensive_ips:
        number_of_violations = offensive_ips[ip]
        if address_in_whitelist(ip, white_list_networks):
            print('Ignore ' + ip + ': in whitelist network (' + str(number_of_violations) + ' attempts)')
            continue
        # print('IP ' + ip + ' seen ' + str(gatheredIPs[ip]) + ' times ')
        if number_of_violations > number_of_attempts_allowed:
            # Check if already blocked
            if firewall.isIPBlocked(ip):
                print('Ignore ' + ip + ': already blocked (' + str(number_of_violations) + ' attempts)')
                continue

            if public_dbs_checker.isIPReported(ip, days=jail_time):
                print('Block ' + ip + ': public dbs says it must be blocked (' + str(number_of_violations) + ' attempts)')
                firewall.blockIP(ip)
            else:
                if number_of_violations > number_of_attempts_force_block:
                    print('Block ' + ip + ': public dbs dont list it, but number of attempts '
                                          '(' + str(number_of_violations) + ') is above force threshold')
                    firewall.blockIP(ip)
                else:
                    print('Ignore ' + ip + ': public dbs list it and attempts (' + str(number_of_violations) +
                          ') below force threshold')
        else:
            print('Ignore ' + ip + ': not enough attempts (' + str(number_of_violations) + ')')

    # ------------
    # Check entries that are very old in our firewall if we may restore them.
    expired_ips = firewall.getIPsOlderThan(jail_time * 24 * 60 * 60)
    print('Check already-blocked ips if they have expired (' + str(len(expired_ips)) + ')')
    for ip in expired_ips:
        # print('Re-check expired address ' + ip)
        if public_dbs_checker.isIPReported(ip, days=jail_time):
            print('KeepBlocked ' + ip + ': public dbs say this IP should still be blocked')
            firewall.updateBlockedIPDate(ip)
        else:
            print('UnBlock ' + ip + ': public dbs say this IP can be safely removed from firewall')
            firewall.unblockIP(ip)
    print('All done. Good bye!')


if __name__ == '__main__':
    main()
