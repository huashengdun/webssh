/*jslint browser:true */

var jQuery;
var wssh = {};

$.fn.serializeObject = function() {  
  var o = {};  
  var a = this.serializeArray();  
  $.each(a, function() {  
      if (o[this.name]) {  
          if (!o[this.name].push) {  
              o[this.name] = [ o[this.name] ];  
          }  
          o[this.name].push(this.value || '');  
      } else {  
          o[this.name] = this.value || '';  
      }  
  });  
  return o;  
}

jQuery(function($){
  var status = $('#status'),
      btn = $('.btn-primary'),
      style = {},
      title_text = 'WebSSH',
      title_element = document.querySelector('title'),
      debug = document.querySelector('#connect').noValidate,
      DISCONNECTED = 0,
      CONNECTING = 1,
      CONNECTED = 2,
      state = DISCONNECTED,
      messages = {1: 'This client is connecting ...', 2: 'This client is already connnected.'},
      key_max_size = 16384,
      form_id = '#connect',
      fields = ['hostname', 'port', 'username', 'password'],
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

  restore_items(fields);

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

    reader.onload = function() {
      var text;
      try {
        text = decoder.decode(reader.result);
      } catch (TypeError) {
        console.log('Decoding error happened.');
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


  function log_status(text) {
    status.text(text);
    console.log(text);
  }


  function ajax_complete_callback(resp) {
    btn.prop('disabled', false);

    if (resp.status !== 200) {
      log_status(resp.status + ': ' + resp.statusText);
      state = DISCONNECTED;
      return;
    }

    var msg = resp.responseJSON;
    if (msg.status) {
      log_status(msg.status);
      state = DISCONNECTED;
      return;
    }

    var ws_url = window.location.href.replace('http', 'ws'),
        join = (ws_url[ws_url.length-1] === '/' ? '' : '/'),
        url = ws_url + join + 'ws?id=' + msg.id,
        sock = new window.WebSocket(url),
        encoding = 'utf-8',
        decoder = new window.TextDecoder('utf-8'),
        terminal = document.getElementById('#terminal'),
        term = new window.Terminal({
          cursorBlink: true,
        });

    console.log(url);
    if (!msg.encoding) {
      console.log('Unable to detect the default encoding of your server');
      msg.encoding = encoding;
    } else {
      console.log('The deault encoding of your server is ' + msg.encoding);
    }

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
      if (!new_encoding) {
        console.log('An encoding is required');
        return;
      }

      try {
        decoder = new window.TextDecoder(new_encoding);
        encoding = decoder.encoding;
        console.log('Set encoding to ' + encoding);
      } catch (RangeError) {
        console.log('Unknown encoding ' + new_encoding);
      }
    }

    wssh.set_encoding = set_encoding;
    set_encoding(msg.encoding);


    wssh.geometry = function() {
      // for console use
      var geometry = current_geometry();
      console.log('Current window geometry: ' + JSON.stringify(geometry));
    };

    wssh.send = function(data) {
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
        data = data.trim() + '\r';
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

    wssh.resize = function(cols, rows) {
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
      state = CONNECTED;
      title_element.text = title_text;
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
      state = DISCONNECTED;
      title_text = 'WebSSH';
      title_element.text = title_text;
    };

    $(window).resize(function(){
      if (term) {
        resize_terminal(term);
      }
    });
  }


  function wrap_object(opts) {
    var obj = {};

    obj.get = function(attr) {
      return opts[attr] || '';
    };

    obj.set = function(attr, val) {
      opts[attr] = val;
    };

    return obj;
  }


  function normalize_data(data) {
    var i, attr, val;
    var attrs = fields.concat('privatekey');

    for (i = 0; i < attrs.length; i++) {
      attr = attrs[i];
      val = data.get(attr);
      if (typeof val === 'string') {
        data.set(attr, val.trim());
      }
    }
  }


  function validate_form_data(data) {
    normalize_data(data);

    var hostname = data.get('hostname'),
        port = data.get('port'),
        username = data.get('username'),
        pk = data.get('privatekey'),
        result = {'vaiid': false},
        msg, size;

    if (!hostname) {
      msg = 'Need value hostname';
    } else if (!port) {
      msg = 'Need value port';
    } else if (!username) {
      msg = 'Need value username';
    } else if (!hostname_tester.test(hostname)) {
      msg =  'Invalid hostname: ' + hostname;
    } else if (port <= 0 || port > 63335) {
      msg = 'Invalid port: ' + port;
    } else {
      if (pk) {
        size = pk.size || pk.length;
        if (size > key_max_size) {
          msg = 'Invalid private key: ' + pk.name || pk;
        }
      }
    }

    if (!msg || debug) {
      result.valid = true;
      msg = username + '@' + hostname + ':'  + port;
    }

    result.msg = msg;
    return result;
  }


  function connect_without_options() {
    // use data from the form
    var form = document.querySelector(form_id),
        url = form.action,
        data = $(form_id).serializeObject(),
        pk = data['privatekey'];

    function ajax_post() {
      store_items(fields, wrap_object(data));

      status.text('');
      btn.prop('disabled', true);

      $.ajax({
          url: url,
          type: 'post',
          data: data,
          complete: ajax_complete_callback,
          cache: false
      });
    }

    var result = validate_form_data(wrap_object(data));
    if (!result.valid) {
      log_status(result.msg);
      return;
    }

    if (pk && pk.size && !debug) {
      read_file_as_text(pk, function(text) {
        if (text === undefined) {
            log_status('Invalid private key: ' + pk.name);
        } else {
          ajax_post();
        }
      });
    } else {
      ajax_post();
    }

    return result.msg;
  }


  function connect_with_options(data) {
    // use data from the arguments
    var form = document.querySelector(form_id),
        url = data.url || form.action,
        _xsrf = form.querySelector('input[name="_xsrf"]');

    var result = validate_form_data(wrap_object(data));
    if (!result.valid) {
      console.log(result.msg);
      return;
    }

    data._xsrf = _xsrf.value;

    $.ajax({
        url: url,
        type: 'post',
        data: data,
        complete: ajax_complete_callback
    });

    return result.msg;
  }


  function connect(hostname, port, username, password, privatekey) {
    // for console use
    var result, opts;

    if (state !== DISCONNECTED) {
      console.log(messages[state]);
      return;
    }

    if (hostname === undefined) {
      result = connect_without_options();
    } else {
      if (typeof hostname === 'string') {
        opts = {
          hostname: hostname,
          port: port,
          username: username,
          password: password,
          privatekey: privatekey
        };
      } else {
        opts = hostname;
      }

      result = connect_with_options(opts);
    }

    if (result) {
      state = CONNECTING;
      title_text = result;
    }
  }

  wssh.connect = connect;

  $(form_id).submit(function(event){
    event.preventDefault();
    connect();
  });

});
