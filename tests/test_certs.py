"""
Tests around PKey-derived certificate identity files.
"""

import unittest
from itertools import product
from paramiko.py3compat import StringIO

from cryptography.hazmat.primitives.asymmetric import rsa
from paramiko import Message, RSAKey
from paramiko.py3compat import byte_chr
from paramiko.rsacert import RSACert

from test_pkey import PUB_RSA, SIGNED_RSA
from util import test_path


PUB_RSA_CERT = 'ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgSMQNY/NloAtYIUsc0Hn+iESDMQSes4l6bLaQfZh5NxwAAAABIwAAAIEA049W6geFpmsljTwfvI1UmKWWJPNFI74+vNKTk4dmzkQY2yAMs6FhlvhlI8ysU4oj71ZsRYMecHbBbxdN79+JRFVYTKaLqjwGENeTd+yv4q+V2PvZv3fLnzApI3l7EJCqhWwJUHJ1jAkZzqDx0tyOL4uoZpww3nmE0kb3y21tH4cAAAAAAAAAAAAAAAEAAAANdXNlcl91c2VybmFtZQAAAAwAAAAIdXNlcm5hbWUAAAAAVWQGuAAAAABXQ+kGAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAMpIMaZW0F/Fie0PcfMTQBZ902htZbGoszPpbGagDUUn7EcBXzbbwyTuSGHwbSsDvJW5JTNCpfJSsrcBDNY0XV5qpsLGE6DMLMAwWztwwrV/bbd2cjcVZJDAcH2S9YmGoscbjYD/FljjA5VYyI5VjYpMgRL1p+AqXOpl/PtQn09ZCrZ8dbPHhGBswFQww1GkOPUMP/iaoG+lwu7VmjhLi2Mf7TX1ce9B8T2VhTdQLtuR7S0jKaS7RgR7wdabAk6XzKJWhMyzXU7qsp9EdIr3axk27+lbj8nS2ya4wrwRMRacZRcvgWVFhh+EROp1DDWJcjVYJFMaeIu5MuUKrKtbVZ0AAAEPAAAAB3NzaC1yc2EAAAEAihMznF3UeBbQDWfh/yGHAk5QbK8cO1OVdenUgtxPpiYlqtc9jiqgSCDbBfZecAbNgpGACO1GamR8E2d3ZsEH+BRV6CWlL1/XMfatKREiseTh7BCyJetDTANbV9uuCqDrbt7r/V4uko61lJY+AaequSNNVVq5+7qhdpFH44TqXa0Yd7TMGU0Ss/Wsr+Mdpu1Bs5wDXWTrOsdDz5Ss66pd7eA14OZ/ihbJhMP7wPibqFi0B+wy2FlhZOShMmrDokjmRQkUzf3I0wir13hbF55AsofP+cEF4MZU/HE5yVbbTXdEXL5ry4B921QGvmLvCsL1ee2wTRWtbb4JRNNaIDg5HQ==' # noqa


class RSACertTests(unittest.TestCase):
    def test_load_cert_and_key(self):
        # Test matrix of most of the silly ways we currently support
        # instantiating the object re: cert and key sources. Corner cases get
        # their own tests below.
        cert_kwargses = [
            dict(cert_filename=test_path('test_rsa-cert.pub')),
            dict(cert_file_obj=StringIO(PUB_RSA_CERT)),
            # TODO: msg, data, and key
        ]
        privkey_path = test_path('test_rsa.key')
        privkey_pass_path = test_path('test_rsa_password.key')
        key_kwargses = [
            # Unprotected private key
            dict(pkey_filename=privkey_path),
            dict(pkey_file_obj=open(privkey_path)),
            # Password-protected private key
            dict(pkey_filename=privkey_pass_path, password='television'),
            dict(pkey_file_obj=open(privkey_pass_path), password='television'),
        ]
        expected_pub_base64 = PUB_RSA.split()[1]
        expected_privkey = RSAKey(filename=privkey_path)
        for cert_kwargs, key_kwargs in product(cert_kwargses, key_kwargses):
            # Build from union of kwargs
            cert = RSACert(**dict(key_kwargs, **cert_kwargs))
            # Make sure cert part looks good
            self.assertEqual('ssh-rsa-cert-v01@openssh.com', cert.get_name())
            self.assertEqual(
                expected_pub_base64,
                cert.get_public_key().get_base64(),
            )
            self.assertTrue(cert.verify_certificate_signature())
            # Make sure key part instantiated OK
            self.assertTrue(isinstance(cert.key, rsa.RSAPrivateKey))
            self.assertEqual(
                expected_privkey.key.private_numbers(),
                cert.key.private_numbers(),
            )
            # Reset any FLOs (meh)
            for value in cert_kwargs.values() + key_kwargs.values():
                if hasattr(value, 'seek') and callable(value.seek):
                    value.seek(0)

    def test_implicit_cert_filename(self):
        # TODO: instantiate with only pkey_filename= kwarg and assert that it
        # loaded that name + -pub.cert
        pass

    def excepts_if_no_cert_data_available(self):
        # TODO: no cert_filename _or_ cert_file_obj _or_ data kwargs
        pass

    def excepts_if_private_key_is_not_given(self):
        # TODO: no msg, data, pkey_filename or key
        pass

    def excepts_if_only_public_key_is_given(self):
        # TODO: not 100% sure this should actually except tho
        # TODO: but, data/pkey_filename/key are public-key material only, no
        # private. In that case, why did the user bother? That should also be
        # in the cert...
        # TODO: anyway test would be if msg/data/pkey_filename/key are given,
        # but they only contain a public key
        pass

    def excepts_if_public_numbers_mismatch(self):
        # TODO: given key isn't actually the match of the certified one!
        pass

    def excepts_if_key_data_given_more_than_one_way(self):
        # TODO: more than one of data, msg, pkey_filename or pkey_file_obj; all
        # combos of these.
        pass

    def excepts_if_cert_data_given_more_than_one_way(self):
        # TODO: cert data given via both cert_filename and cert_file_obj, or
        # via both msg and cert_filename, or any other combo
        pass

    def test_sign(self):
        cert = RSACert(
            pkey_filename=test_path('test_rsa.key'),
            cert_file_obj=StringIO(PUB_RSA_CERT),
        )
        msg = cert.sign_ssh_data(b'ice weasels')
        self.assertTrue(type(msg) is Message)
        msg.rewind()
        self.assertEqual('ssh-rsa', msg.get_text())
        sig = bytes().join(
            [byte_chr(int(x, 16)) for x in SIGNED_RSA.split(':')]
        )
        self.assertEqual(sig, msg.get_binary())
        msg.rewind()
        pub = cert.get_public_key()
        self.assertTrue(pub.verify_ssh_sig(b'ice weasels', msg))

    def test_compare_public_keys(self):
        cert_with_private_key = RSACert(
            pkey_filename=test_path('test_rsa.key'),
            cert_file_obj=StringIO(PUB_RSA_CERT),
        )
        cert_without_private_key = RSACert(
            cert_file_obj=StringIO(PUB_RSA_CERT)
        )
        self.assertTrue(cert_with_private_key.can_sign())
        self.assertFalse(cert_without_private_key.can_sign())
        self.assertEqual(
            cert_with_private_key.get_public_key(),
            cert_without_private_key.get_public_key(),
        )

    def vestigial_methods_raise_NotImplementedError(self):
        # TODO: generate
        # TODO: from_private_key_file
        # TODO: from_private_key
        pass


if __name__ == '__main__':
    unittest.main()
