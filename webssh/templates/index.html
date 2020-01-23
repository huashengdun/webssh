<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title> WebSSH </title>
    <link href="static/img/favicon.png" rel="icon" type="image/png">
    <link href="static/css/bootstrap.min.css" rel="stylesheet" type="text/css"/>
    <link href="static/css/xterm.min.css" rel="stylesheet" type="text/css"/>
    <link href="static/css/fullscreen.min.css" rel="stylesheet" type="text/css"/>
    <style>
      .row {
        margin-top: 15px;
        margin-bottom: 10px;
      }

      .container {
        margin-top: 20px;
      }

      .btn {
        margin-top: 15px;
      }

      .btn-danger {
        margin-left: 5px;
      }
      {% if font.family %}
      @font-face {
        font-family: '{{ font.family }}';
        src: url('{{ font.url }}');
      }

      body {
        font-family: '{{ font.family }}';
      }
      {% end %}
    </style>
  </head>
  <body>
    <div id="waiter" style="display: none"> Connecting ... </div>

    <div class="container form-container" style="display: none">
      <form id="connect" action="" method="post" enctype="multipart/form-data"{% if debug %} novalidate{% end %}>
        <div class="row">
          <div class="col">
            <label for="Hostname">Hostname</label>
            <input class="form-control" type="text" id="hostname" name="hostname" value="" required>
          </div>
          <div class="col">
            <label for="Port">Port</label>
            <input class="form-control" type="number" id="port" name="port" placeholder="22" value="" min=1 max=65535>
          </div>
        </div>
        <div class="row">
          <div class="col">
            <label for="Username">Username</label>
            <input class="form-control" type="text" id="username" name="username" value="" required>
          </div>
          <div class="col">
            <label for="Password">Password</label>
            <input class="form-control" type="password" id="password" name="password" value="">
          </div>
        </div>
        <div class="row">
          <div class="col">
            <label for="Username">Private Key</label>
            <input class="form-control" type="file" id="privatekey" name="privatekey" value="">
          </div>
          <div class="col">
            <label for="Passphrase">Passphrase</label>
            <input class="form-control" type="password" id="passphrase" name="passphrase" value="">
          </div>
        </div>
        <div class="row">
          <div class="col">
            <label for="totp">Totp (time-based one-time password)</label>
            <input class="form-control" type="password" id="totp" name="totp" value="">
          </div>
          <div class="col">
          </div>
        </div>
        <input type="hidden" id="term" name="term" value="xterm-256color">
        {% module xsrf_form_html() %}
        <button type="submit" class="btn btn-primary">Connect</button>
        <button type="reset" class="btn btn-danger">Reset</button>
      </form>
    </div>

    <div class="container">
      <div id="status" style="color: red;"></div>
      <div id="terminal"></div>
    </div>

    <script src="static/js/jquery.min.js"></script>
    <script src="static/js/popper.min.js"></script>
    <script src="static/js/bootstrap.min.js"></script>
    <script src="static/js/xterm.min.js"></script>
    <script src="static/js/xterm-addon-fit.min.js"></script>
    <script src="static/js/main.js"></script>
  </body>
</html>
