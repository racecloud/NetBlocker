from .AbuseIPDB import AbuseIPDB
from .Spamhaus import Spamhaus

class PublicDBs:
    def __init__(self, config):
        self._abuse_ip_db = AbuseIPDB(config.get('general', 'AbuseIPDBAPIKey'))
        self._spamhaus = Spamhaus()

    def isIPReported(self, ip, days=30):
        if self._abuse_ip_db.isIPReported(ip, days):
            return True
        if self._spamhaus.isIPReported(ip):
            return True
        return False
