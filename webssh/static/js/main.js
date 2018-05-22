jQuery(function($){

  var status = $('#status'),
      btn = $('.btn-primary'),
      style = {};

  $('form#connect').submit(function(event) {
      event.preventDefault();

      var form = $(this),
          url = form.attr('action'),
          type = form.attr('type'),
          data = new FormData(this);

      if (!data.get('hostname') || !data.get('port') || !data.get('username')) {
        status.text('Hostname, port and username are required.');
        return;
      }

      var pk = data.get('privatekey');
      if (pk && pk.size > 16384) {
        status.text('Key size exceeds maximum value.');
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

  function parse_xterm_style() {
    var text = $('.xterm-helpers style').text();
    var arr = text.split('xterm-normal-char{width:');
    style.width = parseInt(arr[1]) + 1;
    arr = text.split('div{height:');
    style.height = parseInt(arr[1]);
  }

  function current_geometry() {
    if (!style.width || !style.height) {
      parse_xterm_style();
    }
    cols = parseInt(window.innerWidth / style.width);
    rows = parseInt(window.innerHeight / style.height);
    return [cols, rows];
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
        join = (ws_url[ws_url.length-1] == '/' ? '' : '/'),
        url = ws_url + join + 'ws?id=' + msg.id,
        socket = new WebSocket(url),
        terminal = document.getElementById('#terminal'),
        geometry = current_geometry();
        term = new Terminal({
          cursorBlink: true,
          cols: geometry[0],
          rows: geometry[1]
        });

    console.log(url);
    term.on('data', function(data) {
      // console.log(data);
      socket.send(data);
    });

    socket.onopen = function(e) {
      $('.container').hide();
      term.open(terminal, true);
      term.toggleFullscreen(true);
    };

    socket.onmessage = function(msg) {
      var reader = new FileReader();
      reader.onloadend = function(event){
          var decoder = new TextDecoder();
          var text = decoder.decode(reader.result);
          // console.log(text);
          term.write(text);
      };
      reader.readAsArrayBuffer(msg.data);
    };

    socket.onerror = function(e) {
      console.log(e);
    };

    socket.onclose = function(e) {
      console.log(e);
      term.destroy();
      $('.container').show();
      status.text(e.reason);
      btn.prop('disabled', false);
    };
  }

  $(window).resize(function(){
    if (typeof term != 'undefined') {
      geometry = current_geometry();
      term.geometry = geometry;
      term.resize(geometry[0], geometry[1]);
    }
  });

});
