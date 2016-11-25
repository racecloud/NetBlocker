import requests

class AbuseIPDB:
    def __init__(self, APIKey):
        self.APIKey = APIKey
        self.check_url = 'https://www.abuseipdb.com/check/'

    def isIPReported(self, ip, days=30):
        url = self.check_url + ip + '/json?key=' + self.APIKey + '&days=' + str(days)
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            # print(data)
            return len(data) > 0
        else:
            return False

# def main():
#     a = AbuseIPDB('my test key')
#     ips = ['14.189.179.231', '127.0.0.1', '78.83.100.126']
#     for ip in ips:
#         if a.isIPReported(ip):
#             print(ip + ' is reported')
#         else:
#             print(ip + ' is NOT reported')
#
#
# if __name__ == '__main__':
#     main()
