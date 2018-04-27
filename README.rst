WebSSH
------

|Build Status| |codecov| |PyPI - Python Version| |PyPI|

A simple web application to be used as an ssh client to connect to your
ssh servers. It is written in Python, base on tornado and paramiko.

Preview
~~~~~~~

|Login| |Terminal|

Features
~~~~~~~~

-  SSH password authentication supported, including empty password.
-  SSH public-key authentication supported, including DSA RSA ECDSA
   Ed25519 keys.
-  Encrypted keys supported.
-  Fullscreen terminal supported.
-  Terminal window resizable.
-  Compatible with Python 2.7-3.6.

Instructions
~~~~~~~~~~~~

::

    pip install webssh
    wssh

Options
~~~~~~~

::

    # configure listen address and port
    wssh --address='0.0.0.0' --port=8000

    # configure missing host key policy
    wssh --policy=reject

    # configure logging level
    wssh --logging=debug

    # log to file
    wssh --log-file-prefix=main.log

    # more options
    wssh --help

Nginx config example for running this app behind an nginx server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_read_timeout 300;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Real-PORT $remote_port;
    }

Tips
~~~~

-  Try to use Nginx as a front web server (see config example above) and
   enable SSL, this will prevent your ssh credentials from being
   uncovered. Also afterwards the communication between your browser and
   the web server will be encrypted as they use secured websockets.
-  Try to use reject policy as the missing host key policy along with
   your verified known\_hosts, this will prevent man-in-the-middle
   attacks. The idea is that it checks the system host keys
   file("~/.ssh/known\_hosts") and the application host keys
   file("./known\_hosts") in order, if the ssh server's hostname is not
   found or the key is not matched, the connection will be aborted.

.. |Build Status| image:: https://travis-ci.org/huashengdun/webssh.svg?branch=master
   :target: https://travis-ci.org/huashengdun/webssh
.. |codecov| image:: https://codecov.io/gh/huashengdun/webssh/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/huashengdun/webssh
.. |PyPI - Python Version| image:: https://img.shields.io/pypi/pyversions/webssh.svg
.. |PyPI| image:: https://img.shields.io/pypi/v/webssh.svg
.. |Login| image:: https://github.com/huashengdun/webssh/raw/master/preview/login.png
.. |Terminal| image:: https://github.com/huashengdun/webssh/raw/master/preview/terminal.png

