import paramiko
import gzip


class BaseLogScanner:
    def __init__(self, ip):
        self.ip = ip
        self.ssh_client = None
        self.sftp_client = None
        self.scan_dir = '/var/log'
        self.files_prefix = 'mail.log'
        self.ips_list = {}

    def getSuspiciousIPs(self):
        self.ips_list = {}
        self._connect()
        log_files = self.getLogFilesList()
        if log_files is None:
            return []
        for file in log_files:
            if file.endswith('.gz'):
                self.getIPsFromGZFile(file)
            else:
                self.getIPsFromFile(file)
        self._disconnect()

        return self.ips_list

    def _connect(self):
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.connect(self.ip,  allow_agent=True, look_for_keys=True, timeout=10)
        self.sftp_client = self.ssh_client.open_sftp()

    def getLogFilesList(self):
        log_files = self.sftp_client.listdir(self.scan_dir)
        mail_log_files = [f for f in log_files if f.startswith(self.files_prefix)]
        return mail_log_files

    def getIPsFromFile(self, fileName):
        print('Reading plain text file', fileName)
        f = self.sftp_client.file(self.scan_dir + '/' + fileName, mode='r')
        for line in f:
            self.checkFileLine(line)
        f.close()

    def getIPsFromGZFile(self, fileName):
        print('Reading GZipped file', fileName)
        f = self.sftp_client.file(self.scan_dir + '/' + fileName, mode='rb')
        with gzip.GzipFile(mode='rb', fileobj=f) as fin:
            for line in fin:
                self.checkFileLine(line)
        f.close()

    def checkFileLine(self, line):
        return False

    def _disconnect(self):
        self.sftp_client.close()
        self.ssh_client.close()
