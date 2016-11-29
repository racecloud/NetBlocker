import dns.resolver

# Most of the code comes from https://www.iodigitalsec.com/2014/11/22/dns-black-list-rbl-checking-in-python/

class DNSBLs:
    def __init__(self, config):
        self._dns_resolver = dns.resolver.Resolver()
        # bls = ["zen.spamhaus.org", "spam.abuse.ch", "cbl.abuseat.org", "virbl.dnsbl.bit.nl", "dnsbl.inps.de",
        #        "ix.dnsbl.manitu.net", "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net",
        #        "xbl.spamhaus.org", "pbl.spamhaus.org", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
        #        "dnsbl-3.uceprotect.net", "db.wpbl.info"]
        self._check_domains = ["zen.spamhaus.org"]
        if 'dnsbls' in config['general']:
            self._check_domains = str.split(config.get('general', 'dnsbls'))
        print('DNSBL check will use {0}'.format(self._check_domains))

    def isIPReported(self, ip):
        for domain in self._check_domains:
            try:
                query = '.'.join(reversed(str(ip).split("."))) + "." + domain
                answers = self._dns_resolver.query(query, 'A')
                # if we get here then there could be a listing for this address
                print('DNSBL check for ' + ip + ': listed (got ' + str(answers[0]) + ' from ' + domain + ')')
                # If needed - explode the string to its octets and check the last one -
                # their meanings are explained at https://www.spamhaus.org/zen/
                return True
            except dns.resolver.NXDOMAIN:
                continue
        # If we get here the IP was not listed anywhere
        print('Spamhaus check for ' + ip + ': not reported anywhere')
        return False


def main():
    s = DNSBLs()
    s.isIPReported('201.54.71.153')
    s.isIPReported('8.8.8.8')


if __name__ == '__main__':
    main()
