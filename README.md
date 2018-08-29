## WebSSH

[![Build Status](https://travis-ci.org/huashengdun/webssh.svg?branch=master)](https://travis-ci.org/huashengdun/webssh)
[![codecov](https://codecov.io/gh/huashengdun/webssh/branch/master/graph/badge.svg)](https://codecov.io/gh/huashengdun/webssh)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/webssh.svg)
![PyPI](https://img.shields.io/pypi/v/webssh.svg)


## Introduction

A simple web application to be used as an ssh client to connect to your ssh servers. It is written in Python, base on tornado, paramiko and xterm.js.
```
+---------+     http     +--------+    ssh    +-----------+
| browser | <==========> | webssh | <=======> | ssh server|
+---------+   websocket  +--------+    ssh    +-----------+
```

## Features

* SSH password authentication supported, including empty password.
* SSH public-key authentication supported, including DSA RSA ECDSA Ed25519 keys.
* Encrypted keys supported.
* Fullscreen terminal supported.
* Terminal window resizable.
* Auto detect the ssh server's default encoding.


## Preview

![Login](https://github.com/huashengdun/webssh/raw/master/preview/login.png)
![Terminal](https://github.com/huashengdun/webssh/raw/master/preview/terminal.png)


### Requirements

* Python 2.7/3.4+


### Quickstart

1. Install this app `pip install webssh`
2. Start a webserver `wssh`
3. Open your browser, navigate to `127.0.0.1:8888`
4. Input your data, submit the form.


### Installation options

Install from the pypi repository, may not the latest version
```
pip install webssh
```

Install from the github repository, always the latest version
```
pip install https://github.com/huashengdun/webssh/archive/master.zip
```

### Server options

```bash
# listen address and port
wssh --address='0.0.0.0' --port=8000

# missing host key policy
wssh --policy=reject

# logging level
wssh --logging=debug

# log to file
wssh --log-file-prefix=main.log

# more options
wssh --help
```

### Use console


```javascript
// set a new encoding for client to use
wssh.set_encoding(encoding);

// reset encoding to use the default one
wssh.reset_encoding();

// connect to your ssh server
wssh.connect(hostname, port, username, password, privatekey);

// without argument, wssh will use the form data to connect
wssh.connect();

// define a mapping object
var opts = {
  hostname: 'hostname',
  port: 'port',
  username: 'username',
  password: 'password',
  privatekey: 'the private key text'
};
wssh.connect(opts);

// send a command to the server
wssh.send('ls -l');
```

### Tests

Use unittest to run all tests
```
python -m unittest discover tests
```

Use pytest to run all tests
```
python -m pytest tests
```

### An example of config  for running this app behind an Nginx server

```nginx
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
```

## Tips

* Try to use Nginx as a front web server (see config example above) and enable SSL, this will prevent your ssh credentials from being uncovered. Also afterwards the communication between your browser and the web server will be encrypted as they use secured websockets.
* Try to use reject policy as the missing host key policy along with your verified known_hosts, this will prevent man-in-the-middle attacks. The idea is that it checks the system host keys file("~/.ssh/known_hosts") and the application host keys file("./known_hosts") in order, if the ssh server's hostname is not found or the key is not matched, the connection will be aborted.
