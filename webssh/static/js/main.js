var jQuery;
var wssh = {};


jQuery(function($){
  /*jslint browser:true */

  var status = $('#status'),
      btn = $('.btn-primary'),
      style = {},
      names = ['hostname', 'port', 'username', 'password'];


  function store_items(names, data) {
    var i, name;

    for (i = 0; i < names.length; i++) {
      name = names[i];
      window.localStorage.setItem(name, data.get(name));
    }
  }

  function restore_items(names) {
    var i, name, value;

    for (i=0; i < names.length; i++) {
      name = names[i];
      value = window.localStorage.getItem(name) || '';
      $('#'+name).val(value);
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


  wssh.window_geometry = function() {
    // for console use
    var geometry = current_geometry();
    console.log('Current window geometry: ' + JSON.stringify(geometry));
  };


  function format_geometry(cols, rows) {
    return JSON.stringify({'cols': cols, 'rows': rows});
  }


  function callback(msg) {
    // console.log(msg);
    if (msg.status) {
      status.text(msg.status);
      setTimeout(function(){
        btn.prop('disabled', false);
      }, 3000);
      return;
    }

    var ws_url = window.location.href.replace('http', 'ws'),
        join = (ws_url[ws_url.length-1] === '/' ? '' : '/'),
        url = ws_url + join + 'ws?id=' + msg.id,
        sock = new window.WebSocket(url),
        encoding = msg.encoding,
        terminal = document.getElementById('#terminal'),
        term = new window.Terminal({
          cursorBlink: true,
        });

    console.log(url);
    console.log('The deault encoding of your server is ' + encoding);
    // wssh.sock = sock;
    // wssh.term = term;
    var test_decoder;

    function resize_terminal (term) {
      var geometry = current_geometry();
      term.on_resize(geometry.cols, geometry.rows);
    }

    wssh.websocket_send = function (data) {
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

    wssh.set_encoding = function (new_encoding) {
      // for console use
      if (new_encoding === undefined) {
        return;
      }

      try {
        test_decoder = new window.TextDecoder(new_encoding);
      } catch(TypeError) {
        console.log('Unknown encoding ' + new_encoding);
      } finally {
        if (test_decoder !== undefined) {
          test_decoder = undefined;
          encoding = new_encoding;
          console.log('Set encoding to ' + encoding);
        }
      }
    };

    wssh.reset_encoding = function () {
      // for console use
      encoding = msg.encoding;
      console.log('Reset encoding to ' + msg.encoding);
    };

    wssh.resize_terminal = function (cols, rows) {
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


    term.on_resize = function (cols, rows) {
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
    };

    sock.onmessage = function(msg) {
      var reader = new window.FileReader();

      reader.onloadend = function(){
        var decoder = new window.TextDecoder(encoding);
        var text = decoder.decode(reader.result);
        // console.log(text);
        if (term) {
          term.write(text);
          if (!term.resized) {
            resize_terminal(term);
            term.resized = true;
          }
        }
      };

      reader.readAsArrayBuffer(msg.data);
    };

    sock.onerror = function(e) {
      console.log(e);
    };

    sock.onclose = function(e) {
      console.log(e);
      term.destroy();
      term = undefined;
      sock = undefined;
      $('.container').show();
      status.text(e.reason);
      btn.prop('disabled', false);
    };

    $(window).resize(function(){
      if (term) {
        resize_terminal(term);
      }
    });
  }


  $('form#connect').submit(function(event) {
      event.preventDefault();

      var form = $(this),
          url = form.attr('action'),
          type = form.attr('method'),
          data = new FormData(this),
          hostname = data.get('hostname'),
          port = data.get('port'),
          username = data.get('username'),
          key_max_size = 16384,
          hostname_tester = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))|(^\s*((?=.{1,255}$)(?=.*[A-Za-z].*)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*)\s*$)/;

      if (!hostname || !port || !username) {
        status.text('Fields hostname, port and username are all required.');
        return;
      }

      if (!hostname_tester.test(hostname)) {
        status.text('Not a valid hostname ' + hostname);
        return;
      }

      if (port <= 0 || port > 63335) {
        status.text('Not a valid port ' + port);
        return;
      }

      var pk = data.get('privatekey');
      if (pk && pk.size > key_max_size) {
        status.text('Key size exceeds the maximum value.');
        return;
      }

      store_items(names, data);

      status.text('');
      btn.prop('disabled', true);

      $.ajax({
          url: url,
          type: type,
          data: data,
          success: callback,
          cache: false,
          contentType: false,
          processData: false
      });
  });
});
