var jQuery;
var wssh = {};


jQuery(function($){
  /*jslint browser:true */

  var status = $('#status'),
      btn = $('.btn-primary'),
      style = {};


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


  wssh.window_size = function() {
    var geo = current_geometry();
    console.log('Current window size: ' + geo.cols + ',' + geo.rows);
  };


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

    wssh.set_encoding = function (new_encoding) {
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
      encoding = msg.encoding;
      console.log('Reset encoding to ' + msg.encoding);
    };

    wssh.resize_terminal = function (raw_cols, raw_rows) {
      // for console use
      var cols = parseInt(raw_cols, 10),
          rows = parseInt(raw_rows, 10),
          valid_args = false;

      if (cols > 0 && rows > 0)  {
        var geometry = current_geometry();
        if (cols <= geometry.cols && rows <= geometry.rows) {
          valid_args = true;
        }
      }

      if (!valid_args) {
        console.log('Invalid arguments: ' + raw_cols + ',' + raw_rows);
      } else {
        term.on_resize(cols, rows);
      }
    };

    term.on_resize = function (cols, rows) {
      if (cols !== this.geometry[0] || rows !== this.geometry[1]) {
        console.log('Resizing terminal size to: ' + cols + ',' + rows);
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
        term.write(text);
        if (!term.resized) {
          resize_terminal(term);
          term.resized = true;
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
      $('.container').show();
      status.text(e.reason);
      btn.prop('disabled', false);
    };

    $(window).resize(function(){
      resize_terminal(term);
    });
  }


  $('form#connect').submit(function(event) {
      event.preventDefault();

      var form = $(this),
          url = form.attr('action'),
          type = form.attr('method'),
          data = new FormData(this);

      if (!data.get('hostname') || !data.get('port') || !data.get('username')) {
        status.text('Hostname, port and username are required.');
        return;
      }

      var pk = data.get('privatekey');
      if (pk && pk.size > 16384) {
        status.text('Key size exceeds the maximum value.');
        return;
      }

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
