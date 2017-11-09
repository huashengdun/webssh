## WebSSH
A simple web application to be used as an ssh client to connect to your ssh servers. It is written in Python, base on Tornado and Paramiko.

### Preview
![Login](https://github.com/huashengdun/webssh/raw/master/preview/login.png)
![Terminal](https://github.com/huashengdun/webssh/raw/master/preview/terminal.png)

### Install dependencies
```
$ pip install -r requirements.txt
```

### Run

```
$ python main.py
```

### Help

```
$ python main.py --help
```

### Python versions supported ?
```
Only tested with Python versions 2.7.12 and 3.5.2 on Ubuntu 16.04. 
```

### A config example for putting Nginx as a front web server
```
location / { 
    proxy_pass http://127.0.0.1:8888;
    proxy_http_version 1.1;
    proxy_read_timeout 300;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
} 
