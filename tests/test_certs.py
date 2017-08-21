"""
Tests around PKey-derived certificate identity files.
"""

import unittest
from paramiko.py3compat import StringIO

from paramiko import Message
from paramiko.py3compat import byte_chr
from paramiko.rsacert import RSACert

from test_pkey import PUB_RSA, SIGNED_RSA
from util import test_path


PUB_RSA_CERT = 'ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgSMQNY/NloAtYIUsc0Hn+iESDMQSes4l6bLaQfZh5NxwAAAABIwAAAIEA049W6geFpmsljTwfvI1UmKWWJPNFI74+vNKTk4dmzkQY2yAMs6FhlvhlI8ysU4oj71ZsRYMecHbBbxdN79+JRFVYTKaLqjwGENeTd+yv4q+V2PvZv3fLnzApI3l7EJCqhWwJUHJ1jAkZzqDx0tyOL4uoZpww3nmE0kb3y21tH4cAAAAAAAAAAAAAAAEAAAANdXNlcl91c2VybmFtZQAAAAwAAAAIdXNlcm5hbWUAAAAAVWQGuAAAAABXQ+kGAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAMpIMaZW0F/Fie0PcfMTQBZ902htZbGoszPpbGagDUUn7EcBXzbbwyTuSGHwbSsDvJW5JTNCpfJSsrcBDNY0XV5qpsLGE6DMLMAwWztwwrV/bbd2cjcVZJDAcH2S9YmGoscbjYD/FljjA5VYyI5VjYpMgRL1p+AqXOpl/PtQn09ZCrZ8dbPHhGBswFQww1GkOPUMP/iaoG+lwu7VmjhLi2Mf7TX1ce9B8T2VhTdQLtuR7S0jKaS7RgR7wdabAk6XzKJWhMyzXU7qsp9EdIr3axk27+lbj8nS2ya4wrwRMRacZRcvgWVFhh+EROp1DDWJcjVYJFMaeIu5MuUKrKtbVZ0AAAEPAAAAB3NzaC1yc2EAAAEAihMznF3UeBbQDWfh/yGHAk5QbK8cO1OVdenUgtxPpiYlqtc9jiqgSCDbBfZecAbNgpGACO1GamR8E2d3ZsEH+BRV6CWlL1/XMfatKREiseTh7BCyJetDTANbV9uuCqDrbt7r/V4uko61lJY+AaequSNNVVq5+7qhdpFH44TqXa0Yd7TMGU0Ss/Wsr+Mdpu1Bs5wDXWTrOsdDz5Ss66pd7eA14OZ/ihbJhMP7wPibqFi0B+wy2FlhZOShMmrDokjmRQkUzf3I0wir13hbF55AsofP+cEF4MZU/HE5yVbbTXdEXL5ry4B921QGvmLvCsL1ee2wTRWtbb4JRNNaIDg5HQ=='


class RSACertTests(unittest.TestCase):
    def test_load_rsa_cert(self):
        cert = RSACert(filename=test_path('test_rsa.key'),
                       cert_file_obj=StringIO(PUB_RSA_CERT))
        self.assertEqual('ssh-rsa-cert-v01@openssh.com', cert.get_name())
        self.assertEqual(PUB_RSA.split()[1],
                         cert.get_public_key().get_base64())
        self.assertTrue(cert.verify_certificate_signature())

    def test_load_rsa_cert_password(self):
        cert = RSACert(filename=test_path('test_rsa_password.key'),
                       cert_file_obj=StringIO(PUB_RSA_CERT),
                       password='television')
        self.assertEqual('ssh-rsa-cert-v01@openssh.com', cert.get_name())
        self.assertEqual(PUB_RSA.split()[1],
                         cert.get_public_key().get_base64())
        self.assertTrue(cert.verify_certificate_signature())

    def test_sign_rsa_cert(self):
        cert = RSACert(filename=test_path('test_rsa.key'),
                       cert_file_obj=StringIO(PUB_RSA_CERT))
        msg = cert.sign_ssh_data(b'ice weasels')
        self.assertTrue(type(msg) is Message)
        msg.rewind()
        self.assertEqual('ssh-rsa', msg.get_text())
        sig = bytes().join(
            [byte_chr(int(x, 16)) for x in SIGNED_RSA.split(':')])
        self.assertEqual(sig, msg.get_binary())
        msg.rewind()
        pub = cert.get_public_key()
        self.assertTrue(pub.verify_ssh_sig(b'ice weasels', msg))

    def test_compare_rsa_cert(self):
        cert_with_private_key = RSACert(
            filename=test_path('test_rsa.key'),
            cert_file_obj=StringIO(PUB_RSA_CERT))
        cert_without_private_key = RSACert(
            cert_file_obj=StringIO(PUB_RSA_CERT))

        self.assertTrue(cert_with_private_key.can_sign())
        self.assertFalse(cert_without_private_key.can_sign())
        self.assertEqual(cert_with_private_key.get_public_key(),
                         cert_without_private_key.get_public_key())


if __name__ == '__main__':
    unittest.main()
