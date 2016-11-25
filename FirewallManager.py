from MikrotikApi import ApiRos
import socket
import time


class FirewallManager:
    def __init__(self, config, addressListName='Complete Block'):
        self.ip = config.get('general', 'firewallip')
        self.username = config.get('general', 'firewallusername')
        self.password = config.get('general', 'firewallpassword')
        self.addressListName = addressListName
        self.dateCommentPrefix = 'Date: '
        self.dateCommentSuffix = ';'

        self.blockedIPs = None

        self.socket = None
        self.api = None
        self.connect()

    def connect(self):
        for res in socket.getaddrinfo(self.ip, "8728", socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                 self.socket = socket.socket(af, socktype, proto)
            except (socket.error):
                self.socket = None
                continue
            try:
                self.socket.connect(sa)
            except (socket.error):
                self.socket.close()
                self.socket = None
                continue
            break
        if self.socket is None:
            print('could not open socket')
            return

        self.api = ApiRos(self.socket);
        self.api.login(self.username, self.password)
        self.getBlockedIPs()

    def getBlockedIPs(self):
        if self.blockedIPs is not None:
            return self.blockedIPs
        self.api.writeSentence(['/ip/firewall/address-list/print'])
        response = self.readReplyUntilDone()
        # Parse the response lines
        blockedIPs = []
        for raw_entry in response:
            entry = self.parse_return_sentence(raw_entry)
            if 'address' in entry and 'list' in entry and 'disabled' in entry:
                # These check filter out addresses that hae some manual intervention
                if entry['disabled'] != 'false':
                    continue
                if self.addressListName is not None and entry['list'] != self.addressListName:
                    continue
                if 'comment' not in entry:
                    continue
                if not entry['comment'].startswith(self.dateCommentPrefix):
                    continue
                blockedIPs.append(entry)
        self.blockedIPs = blockedIPs
        return blockedIPs

    def parse_return_sentence(self, raw_entry):
        obj = {}
        for line in raw_entry:
            if line.startswith('!'):
                continue
            elif line.startswith('='):
                line = line[1:]
                chunk = line.split('=', 2)
                if len(chunk) > 1:
                    obj[chunk[0]] = chunk[1]
        return obj

    def readReplyUntilDone(self):
        response = []
        while 1:
            input = self.api.readSentence()
            if len(input) > 0:
                first_line = input[0]
                if first_line == '!re':
                    response.append(input)
                else:
                    break
            else:
                break
        return response

    def readDoneReturn(self):
        input = self.api.readSentence()
        if len(input) >= 2 and input[0] == '!done':
            parsed = self.parse_return_sentence(input)
            if 'ret' in parsed:
                return parsed['ret']
        return None

    def blockIP(self, ip):
        t = time.time()
        dateComment = self.dateCommentPrefix + \
                      str(int(t)) + ' ' + time.strftime('%d-%m-%Y %H:%M:%S', time.gmtime(t)) + \
                      self.dateCommentSuffix
        self.api.writeSentence(['/ip/firewall/address-list/add',
                                '=address=' + ip,
                                '=list=' + self.addressListName,
                                '=comment=' + dateComment])
        id = self.readDoneReturn()
        newEntry = {'address': ip,
                    'list': self.addressListName,
                    'comment': dateComment,
                    'dynamic': 'false', 'disabled': 'false', '.id': id}
        self.blockedIPs.append(newEntry)
        return id

    def findBlockedIP(self, ip):
        if self.blockedIPs is not None:
            entry = [x for x in self.blockedIPs if x['address'] == ip]
            if entry:
                return entry

        self.api.writeSentence(['/ip/firewall/address-list/print',
                                '?address=' + ip,
                                '?list=' + self.addressListName,
                                '?#&'])
        reply = self.readReplyUntilDone()
        foundEntries = []
        if len(reply) > 0:
            for entry in reply:
                if entry[0] != '!re':
                    continue
                parsedEntry = self.parse_return_sentence(entry)
                foundEntries.append(parsedEntry)
        return foundEntries

    def isIPBlocked(self, ip):
        entry = self.findBlockedIP(ip)
        return len(entry) > 0

    def getBlockedIPDate(self, ip):
        foundEntries = self.findBlockedIP(ip)
        if not foundEntries:
            return None
        entry = foundEntries[0]
        return self.getBlockEntryDate(entry)

    def getBlockEntryDate(self, entry):
        if 'comment' not in entry:
            return 0
        comment = entry['comment']
        if comment.startswith(self.dateCommentPrefix):
            i = len(self.dateCommentPrefix)
            e = comment.index(self.dateCommentSuffix)
            if i > 0 and e > i:
                subs = comment[i:e]
                e = subs.index(' ')
                subs = subs[:e]
                return int(subs)

    def unblockIP(self, ip):
        foundEntries = self.findBlockedIP(ip)
        for entry in foundEntries:
            print(self.getBlockEntryDate(entry))
            id = entry['.id']
            self.api.writeSentence(['/ip/firewall/address-list/remove', '=.id=' + id])
            self.readReplyUntilDone()
            if entry in self.blockedIPs:
                self.blockedIPs.remove(entry)

    def updateBlockedIPDate(self, ip):
        foundEntries = self.findBlockedIP(ip)
        if not foundEntries:
            return None
        entry = foundEntries[0]

        id = entry['.id']
        t = time.time()
        dateComment = self.dateCommentPrefix + \
                      str(int(t)) + ' ' + time.strftime('%d-%m-%Y %H:%M:%S', time.gmtime(t)) + \
                      self.dateCommentSuffix
        self.api.writeSentence(['/ip/firewall/address-list/set',
                                '=.id=' + id,
                                '=comment=' + dateComment])
        self.readReplyUntilDone()
        if entry in self.blockedIPs:
            self.blockedIPs.remove(entry)
            entry['comment'] = dateComment
            self.blockedIPs.append(entry)

    def getIPsOlderThan(self, secondsOld):
        entries = self.getBlockedIPs()
        res = []
        now = time.time()
        for entry in entries:
            date = self.getBlockEntryDate(entry)
            if now - date > secondsOld:
                res.append(entry['address'])
        return res


# def main():
#     f = FirewallManager()
#
#     print(f.getBlockedIPs())
#
#     blockedIndex = f.blockIP('8.8.8.8')
#     print('Blocked with id ' + blockedIndex)
#
#     found = f.findBlockedIP('8.8.8.8')
#     for entry in found:
#         id = entry['.id']
#         print ('Found with id ' + id)
#         f.updateBlockedIPDate(entry['address'])
#
#     f.unblockIP('8.8.8.8')
#
#
# if __name__ == '__main__':
#     main()
