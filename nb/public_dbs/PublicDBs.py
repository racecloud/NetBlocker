from .AbuseIPDB import AbuseIPDB
from .DNSBLs import DNSBLs

class PublicDBs:
    def __init__(self, config):
        self._abuse_ip_db = AbuseIPDB(config.get('general', 'AbuseIPDBAPIKey'))
        self._dnsbls = DNSBLs(config)

    def isIPReported(self, ip, days=30):
        if self._abuse_ip_db.isIPReported(ip, days):
            return True
        if self._dnsbls.isIPReported(ip):
            return True
        return False
