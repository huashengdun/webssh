var jQuery;
var wssh = {};


jQuery(function($){
  /*jslint browser:true */

  var status = $('#status'),
      btn = $('.btn-primary'),
      style = {},
      connected = false,
      key_max_size = 16384,
      form_id = '#connect',
      names = ['hostname', 'port', 'username', 'password'],
      hostname_tester = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))|(^\s*((?=.{1,255}$)(?=.*[A-Za-z].*)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*)\s*$)/;


  function store_items(names, data) {
    var i, name, value;

    for (i = 0; i < names.length; i++) {
      name = names[i];
      value = data.get(name);
      if (value){
        window.localStorage.setItem(name, value);
      }
    }
  }

  function restore_items(names) {
    var i, name, value;

    for (i=0; i < names.length; i++) {
      name = names[i];
      value = window.localStorage.getItem(name);
      if (value) {
        $('#'+name).val(value);
      }
    }
  }

  restore_items(names);

  function parse_xterm_style() {
    var text = $('.xterm-helpers style').text();
    var arr = text.split('xterm-normal-char{width:');
    style.width = parseFloat(arr[1]);
    arr = text.split('div{height:');
    style.height = parseFloat(arr[1]);
  }


  function current_geometry() {
    if (!style.width || !style.height) {
      parse_xterm_style();
    }

    var cols = parseInt(window.innerWidth / style.width, 10) - 1;
    var rows = parseInt(window.innerHeight / style.height, 10);
    return {'cols': cols, 'rows': rows};
  }


  function format_geometry(cols, rows) {
    return JSON.stringify({'cols': cols, 'rows': rows});
  }


  function read_file_as_text(file, callback, decoder) {
    var reader = new window.FileReader();

    if (decoder === undefined) {
      decoder = new window.TextDecoder('utf-8', {'fatal': true});
    }

    reader.onload = function () {
      var text;
      try {
        text = decoder.decode(reader.result);
      } catch (TypeError) {
        console.error('Decoding error happened.');
      } finally {
        if (callback) {
          callback(text);
        }
      }
    };

    reader.onerror = function (e) {
      console.error(e);
    };

    reader.readAsArrayBuffer(file);
  }


  function reset_wssh() {
    var name;

    for (name in wssh) {
      if (wssh.hasOwnProperty(name) && name !== 'connect') {
        delete wssh[name];
      }
    }
  }


  function callback(resp) {
    btn.prop('disabled', false);

    if (resp.status !== 200) {
      console.log(resp);
      status.text('Response code: ' + resp.status);
      return;
    }

    var msg = resp.responseJSON;
    if (msg.status) {
      status.text(msg.status);
      return;
    }

    var ws_url = window.location.href.replace('http', 'ws'),
        join = (ws_url[ws_url.length-1] === '/' ? '' : '/'),
        url = ws_url + join + 'ws?id=' + msg.id,
        sock = new window.WebSocket(url),
        encoding, decoder,
        terminal = document.getElementById('#terminal'),
        term = new window.Terminal({
          cursorBlink: true,
        });

    console.log(url);
    console.log('The deault encoding of your server is ' + msg.encoding);
    // wssh.sock = sock;
    // wssh.term = term;

    function resize_terminal(term) {
      var geometry = current_geometry();
      term.on_resize(geometry.cols, geometry.rows);
    }

    function term_write(text) {
      if (term) {
        term.write(text);
        if (!term.resized) {
          resize_terminal(term);
          term.resized = true;
        }
      }
    }

    function set_encoding(new_encoding) {
      // for console use
      if (new_encoding === undefined) {
        console.log('An encoding is required');
        return;
      }

      try {
        decoder = new window.TextDecoder(new_encoding);
        encoding = new_encoding;
        console.log('Set encoding to ' + encoding);
      } catch(RangeError) {
        console.log('Unknown encoding ' + new_encoding);
      }
    }

    wssh.set_encoding = set_encoding;
    set_encoding(msg.encoding);


    wssh.window_geometry = function() {
      // for console use
      var geometry = current_geometry();
      console.log('Current window geometry: ' + JSON.stringify(geometry));
    };

    wssh.websocket_send = function(data) {
      // for console use
      if (!sock) {
        console.log('Websocket was already closed');
        return;
      }

      if (typeof data !== 'string') {
        console.log('Only string is allowed');
        return;
      }

      try {
        JSON.parse(data);
        sock.send(data);
      } catch (SyntaxError) {
        sock.send(JSON.stringify({'data': data}));
      }
    };

    wssh.reset_encoding = function() {
      // for console use
      if (encoding === msg.encoding) {
        console.log('Already reset to ' + msg.encoding);
      } else {
        set_encoding(msg.encoding);
      }
    };

    wssh.resize_terminal = function(cols, rows) {
      // for console use
      if (term === undefined) {
        console.log('Terminal was already destroryed');
        return;
      }

      var valid_args = false;

      if (cols > 0 && rows > 0)  {
        var geometry = current_geometry();
        if (cols <= geometry.cols && rows <= geometry.rows) {
          valid_args = true;
        }
      }

      if (!valid_args) {
        console.log('Unable to resize terminal to geometry: ' + format_geometry(cols, rows));
      } else {
        term.on_resize(cols, rows);
      }
    };

    term.on_resize = function(cols, rows) {
      if (cols !== this.geometry[0] || rows !== this.geometry[1]) {
        console.log('Resizing terminal to geometry: ' + format_geometry(cols, rows));
        this.resize(cols, rows);
        sock.send(JSON.stringify({'resize': [cols, rows]}));
      }
    };

    term.on('data', function(data) {
      // console.log(data);
      sock.send(JSON.stringify({'data': data}));
    });

    sock.onopen = function() {
      $('.container').hide();
      term.open(terminal, true);
      term.toggleFullscreen(true);
      connected = true;
    };

    sock.onmessage = function(msg) {
      read_file_as_text(msg.data, term_write, decoder);
    };

    sock.onerror = function(e) {
      console.error(e);
    };

    sock.onclose = function(e) {
      console.log(e);
      term.destroy();
      term = undefined;
      sock = undefined;
      reset_wssh();
      $('.container').show();
      status.text(e.reason);
      connected = false;
    };

    $(window).resize(function(){
      if (term) {
        resize_terminal(term);
      }
    });
  }


  function connect() {
    if (connected) {
      console.log('This client was already connected.');
      return;
    }

    var form = document.querySelector(form_id),
        url = form.action,
        data = new FormData(form),
        hostname = data.get('hostname'),
        port = data.get('port'),
        username = data.get('username');

    if (!hostname || !port || !username) {
      status.text('Fields hostname, port and username are all required.');
      return;
    }

    if (!hostname_tester.test(hostname)) {
      status.text('Invalid hostname: ' + hostname);
      return;
    }

    if (port <= 0 || port > 63335) {
      status.text('Invalid port: ' + port);
      return;
    }

    var pk = data.get('privatekey');
    if (pk && pk.size > key_max_size) {
      status.text('Invalid private key: ' + pk.name);
      return;
    }

    store_items(names, data);

    status.text('');
    btn.prop('disabled', true);

    $.ajax({
        url: url,
        type: 'post',
        data: data,
        complete: callback,
        cache: false,
        contentType: false,
        processData: false
    });
  }

  wssh.connect = connect;

  $(form_id).submit(function(event){
      event.preventDefault();
      connect();
  });

});
