========
Paramiko
========

.. Continuous integration and code coverage badges

.. image:: https://travis-ci.org/paramiko/paramiko.svg?branch=master
    :target: https://travis-ci.org/paramiko/paramiko
.. image:: https://coveralls.io/repos/paramiko/paramiko/badge.svg?branch=master&service=github
    :target: https://coveralls.io/github/paramiko/paramiko?branch=master

:Paramiko:    Python SSH module
:Copyright:   Copyright (c) 2003-2009  Robey Pointer <robeypointer@gmail.com>
:Copyright:   Copyright (c) 2013-2015  Jeff Forcier <jeff@bitprophet.org>
:License:     `LGPL <https://www.gnu.org/copyleft/lesser.html>`_
:Homepage:    http://www.paramiko.org/
:API docs:    http://docs.paramiko.org
:Development: https://github.com/paramiko/paramiko


What
----

"Paramiko" is a combination of the esperanto words for "paranoid" and
"friend".  It's a module for Python 2.6+ that implements the SSH2 protocol
for secure (encrypted and authenticated) connections to remote machines.
Unlike SSL (aka TLS), SSH2 protocol does not require hierarchical
certificates signed by a powerful central authority.  You may know SSH2 as
the protocol that replaced Telnet and rsh for secure access to remote
shells, but the protocol also includes the ability to open arbitrary
channels to remote services across the encrypted tunnel (this is how SFTP
works, for example).

It is written entirely in Python (no C or platform-dependent code) and is
released under the GNU Lesser General Public License (`LGPL
<https://www.gnu.org/copyleft/lesser.html>`_).

The package and its API is fairly well documented in the "doc/" folder
that should have come with this archive.


Requirements
------------

- `Python <http://www.python.org/>`_ 2.6, 2.7, or 3.3+ (3.2 should also work,
  but it is not recommended)
- `pycrypto <https://www.dlitz.net/software/pycrypto/>`_ 2.1+
- `ecdsa <https://pypi.python.org/pypi/ecdsa>`_ 0.11+


Installation
------------

For most users, the recommended method to install is via pip::

    pip install paramiko

For more detailed instructions, see the `Installing
<http://www.paramiko.org/installing.html>`_ page on the main Paramiko website.


Portability Issues
------------------

Paramiko primarily supports POSIX platforms with standard OpenSSH
implementations, and is most frequently tested on Linux and OS X.  Windows is
supported as well, though it may not be as straightforward.

Some Windows users whose Python is 64-bit have found that the PyCrypto
dependency ``winrandom`` may not install properly, leading to an
``ImportError``.  In this scenario, you may need to compile ``winrandom``
yourself.  See `Fabric #194 <https://github.com/fabric/fabric/issues/194>`_
for info.

Some Python distributions don't include the UTF-8 string encodings, for
reasons of space (misguided as that is).  If your distribution is
missing encodings, you'll see an error like this::

    LookupError: no codec search functions registered: can't find encoding

This means you need to copy string encodings over from a working system
(it probably only happens on embedded systems, not normal Python
installs).  Valeriy Pogrebitskiy says the best place to look is
``.../lib/python*/encodings/__init__.py``.


Bugs & Support
--------------

:Bug Reports:  `Github <https://github.com/paramiko/paramiko/issues/>`_
:Mailing List: ``paramiko@librelist.com`` (see the `LibreList website
               <http://librelist.com/>`_ for usage details).
:IRC:          ``#paramiko`` on Freenode


Kerberos Support
----------------

Paramiko ships with optional Kerberos/GSSAPI support; for info on the extra
dependencies for this, see the `GSS-API section
<http://www.paramiko.org/installing.html#gssapi>`_
on the main Paramiko website.


Demo
----

Several demo scripts come with Paramiko to demonstrate how to use it.
Probably the simplest demo of all is this::

    import paramiko, base64
    key = paramiko.RSAKey(data=base64.decodestring('AAA...'))
    client = paramiko.SSHClient()
    client.get_host_keys().add('ssh.example.com', 'ssh-rsa', key)
    client.connect('ssh.example.com', username='strongbad', password='thecheat')
    stdin, stdout, stderr = client.exec_command('ls')
    for line in stdout:
        print '... ' + line.strip('\n')
    client.close()

This prints out the results of executing ``ls`` on a remote server. The host
key 'AAA...' should of course be replaced by the actual base64 encoding of the
host key.  If you skip host key verification, the connection is not secure!

The following example scripts (in demos/) get progressively more detailed:

:demo_simple.py:
    Calls invoke_shell() and emulates a terminal/TTY through which you can
    execute commands interactively on a remote server.  Think of it as a
    poor man's SSH command-line client.

:demo.py:
    Same as demo_simple.py, but allows you to authenticate using a private
    key, attempts to use an SSH agent if present, and uses the long form of
    some of the API calls.

:forward.py:
    Command-line script to set up port-forwarding across an SSH transport.

:demo_sftp.py:
    Opens an SFTP session and does a few simple file operations.

:demo_server.py:
    An SSH server that listens on port 2200 and accepts a login for
    'robey' (password 'foo'), and pretends to be a BBS.  Meant to be a
    very simple demo of writing an SSH server.

:demo_keygen.py:
    A key generator similar to OpenSSH ``ssh-keygen(1)`` program with
    Paramiko keys generation and progress functions.

Use
---

The demo scripts are probably the best example of how to use this package.
There is also a lot of documentation, generated with Sphinx autodoc, in the
doc/ folder.

There are also unit tests here::

    $ python ./test.py

Which will verify that most of the core components are working correctly.