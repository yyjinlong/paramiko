"""
Tests around PKey-derived certificate identity files.
"""

import unittest
from itertools import product
from paramiko.py3compat import StringIO

from cryptography.hazmat.primitives.asymmetric import rsa
from paramiko import Message, RSAKey, SSHException
from paramiko.py3compat import byte_chr
from paramiko.rsacert import RSACert

from test_pkey import PUB_RSA, SIGNED_RSA
from util import test_path


with open(test_path('test_rsa-cert.pub')) as fd:
    PUB_RSA_CERT = fd.read()


class RSACertTests(unittest.TestCase):
    def test_load_cert_and_key(self):
        # Test matrix of most of the silly ways we currently support
        # instantiating the object re: cert and key sources. Corner cases get
        # their own tests below.
        cert_kwargses = [
            dict(cert_filename=test_path('test_rsa-cert.pub')),
            dict(cert_file_obj=StringIO(PUB_RSA_CERT)),
            # TODO: msg=, data=
        ]
        privkey_path = test_path('test_rsa.key')
        privkey_pass_path = test_path('test_rsa_password.key')
        key_kwargses = [
            # Unprotected private key
            dict(pkey_filename=privkey_path),
            dict(pkey_file_obj=open(privkey_path)),
            # TODO: key=
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

    def test_excepts_if_no_cert_data_available(self):
        try:
            RSACert()
        # TODO: custom exc subclass
        except SSHException as e:
            err = "Must provide data, msg, cert_filename or cert_file_obj!"
            self.assertEqual(str(e), err)
        else:
            assert False, "Did not raise SSHException!"

    def test_excepts_if_private_key_is_not_given(self):
        # TODO: no pkey_filename, pkey_file_obj, or key
        pass

    def test_excepts_if_only_public_key_is_given(self):
        # TODO: not 100% sure this should actually except tho
        # TODO: but, pkey_filename/pkey_file_obj/key are public-key material
        # only, no private. In that case, why did the user bother? That should
        # also be in the cert...
        # TODO: anyway test would be if msg/data/pkey_filename/key are given,
        # but they only contain a public key
        pass

    def test_excepts_if_public_numbers_mismatch(self):
        # TODO: given key isn't actually the match of the certified one!
        pass

    def test_excepts_if_key_data_given_more_than_one_way(self):
        # TODO: more than one of key, pkey_filename or pkey_file_obj; all
        # combos of these.
        pass

    def test_excepts_if_cert_data_given_more_than_one_way(self):
        # TODO: cert data given via more than one of cert_filename,
        # cert_file_obj, msg, or data. All combos.
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

    def test_vestigial_methods_raise_NotImplementedError(self):
        # TODO: generate
        # TODO: from_private_key_file
        # TODO: from_private_key
        pass


if __name__ == '__main__':
    unittest.main()
