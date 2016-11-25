from BaseLogScanner import BaseLogScanner

class MailLogScanner (BaseLogScanner):
    def __init__(self, config_section):
        BaseLogScanner.__init__(self, config_section)
        self.search_string = config_section.get('searchstring')

    def checkFileLine(self, line):
        if self.search_string in str(line):
            # find the ip address
            cmp = line.split()
            if len(cmp) >= 7:
                ip = str(cmp[6])
                if '[' in ip and ']' in ip:
                    s = ip.index('[')
                    e = ip.index(']')
                    ip = ip[s+1:e]
                    if not ip in self.ips_list:
                        self.ips_list[ip] = 0
                    self.ips_list[ip] += 1

        return False
#
#
# def main():
#     msc = MailLogScanner('srv1')
#     ips = msc.getSuspiciousIPs()
#     print(ips)
#
#
# if __name__ == '__main__':
#     main()
