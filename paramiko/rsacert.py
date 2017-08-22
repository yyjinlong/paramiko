import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from paramiko import util
from paramiko.message import Message
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException


class RSACert(RSAKey):
    """
    Certificate-bearing form of `.RSAKey`, compatible with OpenSSH 5.4+.

    This class may operate in two modes:

    - Private-material-bearing combo object used for authentication _to_ the
      remote end: i.e. you're a client and are using the private key to sign
      the certificate before submitting it to the server. This is considered
      the primary or common use case and is similar to using the OpenSSH client
      with both a private key file and the corresponding certificate file.
    - Public-material-only signed authentication of the remote end: i.e.,
      you're a client and the `RSACert` instance represents the host
      certificate; or vice versa.

    For details on the format of certificate files, see the `official SSH
    certificate format specification
    <http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD>`_.

    Certificate-based authentication can simplify authentication without
    relying upon heavy-weight services such as LDAP. A good (if slightly dated,
    though the basics remain the same) introductory guide to SSH certificates
    can be found in `this DigitalOcean community tutorial
    <https://www.digitalocean.com/community/tutorials/how-to-create-an-ssh-ca-to-validate-hosts-and-clients-with-ubuntu>`_.

    .. note::
        Certificate data *must* be provided (via ``msg``, ``data``,
        ``cert_filename`` or ``cert_file_obj``) but private key data
        (``pkey_filename``, ``pkey_file_obj``) is optional, as per above
        discussion of use cases.

    .. note::
        Only one method of providing either the private key or certificate data
        should be used; for example, providing both ``pkey_filename`` and
        ``pkey_file_obj``, or providing both ``msg`` and ``cert_filename``,
        may result in an error (`ZoP #12
        <https://zen-of-python.info/in-the-face-of-ambiguity-refuse-the-temptation-to-guess.html#12>`_.)

    :param msg:
        A `.Message` object containing the certificate. Note that this
        overrides the ``msg`` argument from the parent class (though as both
        end up providing public key material, the effect is largely the same.)

    :param data:
        Binary data that can be used to instantiate a `.Message`. As with
        ``msg``, this overrides the ``data`` kwarg of the parent class, and
        must contain a full certificate and not just a public key.

    :param str pkey_filename:
        Path to private key file.

    :param str pkey_file_obj:
        File-like object containing private key text.

    :param str cert_filename:
        Path to certificate file.

    :param str cert_file_obj:
        File-like object containing certificate data.

    .. versionadded:: 2.3
    """

    def __init__(self,
        msg=None,
        data=None,
        pkey_filename=None,
        pkey_file_obj=None,
        password=None,
        key=None,
        cert_filename=None,
        cert_file_obj=None,
    ):
        self.nonce = None
        self.key = None
        self.serial = None
        self.type = None
        self.key_id = None
        self.valid_principals = None
        self.valid_after = None
        self.valid_before = None
        self.critical_options = None
        self.extensions = None
        self.reserved = None
        self.signature_key = None
        self.signature = None
        self.d = None
        self.p = None
        self.q = None

        if cert_filename is not None:
            msg = self._load_cert_from_file(cert_filename)
        elif cert_file_obj is not None:
            msg = self._load_cert(cert_file_obj)
        elif cert_filename is None and cert_file_obj is None and data is None:
            raise SSHException(
                'Either a data object or a certificate file must be given')

        # TODO: can't we defer most of this to parent
        if pkey_file_obj is not None:
            self._from_private_key(pkey_file_obj, password)
        elif pkey_filename is not None:
            self._from_private_key_file(pkey_filename, password)

        # TODO: utilize key= kwarg, set to self.key as in RSAKey

        # Normalize to a Message, since certificate files are by definition
        # stored in message format, even on-disk.
        if msg is None and data is not None:
            msg = Message(data)
        if msg is None:
            # TODO: better exception, unless RSAKey does exactly this too
            raise SSHException('Key object may not be empty')
        if msg.get_text() != 'ssh-rsa-cert-v01@openssh.com':
            # TODO: ditto
            raise SSHException('Invalid key')

        # From here, we are simply following the RFC's defined message format
        self.nonce = msg.get_string()

        e = msg.get_mpint()
        n = msg.get_mpint()
        # TODO: bail out if self.key exists & its public numbers != ours!
        # Key might've been set by a private key file. If not, set it from the
        # cert
        if self.key is None:
            self.key = rsa.RSAPublicNumbers(e=e, n=n).public_key(
                default_backend())

        self.serial = msg.get_int64()
        self.type = msg.get_int()
        self.key_id = msg.get_string()
        self.valid_principals = msg.get_string()
        self.valid_after = msg.get_int64()
        self.valid_before = msg.get_int64()
        self.critical_options = msg.get_string()
        self.extensions = msg.get_string()
        self.reserved = msg.get_string()
        self.signature_key = msg.get_string()
        self.signature = msg.get_string()

    @property
    def size(self):
        return util.bit_length(self.public_numbers.n)

    def get_name(self):
        return 'ssh-rsa-cert-v01@openssh.com'

    def get_public_key(self):
        return RSAKey(key=self.key)

    def _message_without_signature(self):
        m = Message()
        m.add_string('ssh-rsa-cert-v01@openssh.com')
        m.add_string(self.nonce)
        m.add_mpint(self.public_numbers.e)
        m.add_mpint(self.public_numbers.n)
        m.add_int64(self.serial)
        m.add_int(self.type)
        m.add_string(self.key_id)
        m.add_string(self.valid_principals)
        m.add_int64(self.valid_after)
        m.add_int64(self.valid_before)
        m.add_string(self.critical_options)
        m.add_string(self.extensions)
        m.add_string(self.reserved)
        m.add_string(self.signature_key)
        return m

    def _message_with_signature(self):
        m = self._message_without_signature()
        m.add_string(self.signature)
        return m

    def asbytes(self):
        return self._message_with_signature().asbytes()

    def verify_certificate_signature(self):
        return RSAKey(data=self.signature_key).verify_ssh_sig(
            self._message_without_signature().asbytes(),
            Message(self.signature))

    def _load_cert_from_file(self, cert_file):
        with open(cert_file, 'r') as f:
            data = self._load_cert(f)
        return data

    def _load_cert(self, cert_file_obj):
        data = cert_file_obj.read().replace('\n', '')
        data = data.split()
        if len(data) > 1:
            data = data[1]
        else:
            data = data[0]
        return Message(base64.b64decode(data.encode('ascii')))

    @staticmethod
    def generate(bits, progress_func=None):
        """
        Not implemented in RSACert because a certificate must be signed by a CA
        and therefore loaded from some pre-existing data
        """
        raise Exception('Not implemented in RSACert')

    @classmethod
    def from_private_key_file(cls, filename, password=None):
        """
        Not implemented in RSACert because certificates cannot be generated
        from private key files
        """
        raise Exception('Not implemented in RSACert')

    @classmethod
    def from_private_key(cls, file_obj, password=None):
        """
        Not implemented in RSACert because certificates cannot be generated
        from private key files
        """
        raise Exception('Not implemented in RSACert')
