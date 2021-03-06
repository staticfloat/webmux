var term,
    charWidth,
    charHeight;

// This chunk of code gratefully stolen/adapted from fit.js
function calculate_character_dimensions() {
  subjectRow = term.rowContainer.firstElementChild;
  contentBuffer = subjectRow.innerHTML;

  subjectRow.style.display = 'inline';
  subjectRow.innerHTML = 'W';
  charWidth = subjectRow.getBoundingClientRect().width;
  subjectRow.style.display = '';
  charHeight = parseInt(subjectRow.offsetHeight);
  subjectRow.innerHTML = contentBuffer;
}

function createTerminal(websocket_url) {
  var terminalContainer = document.getElementById('terminal-container');

  // Clean terminal
  while (terminalContainer.children.length) {
    terminalContainer.removeChild(terminalContainer.children[0]);
  }

  term = new Terminal({
    cursorBlink: true
  });

  protocol = (location.protocol === 'https:') ? 'wss://' : 'ws://';
  socketURL = protocol + location.hostname + ((location.port) ? (':' + location.port) : '') + websocket_url;

  term.open(terminalContainer);
  var socket = new WebSocket(socketURL);
  socket.onopen = function() {
    term.attach(socket);
    term._initialized = true;

    terminalContainer.style.width = '100vw';
    terminalContainer.style.height = '100vh';
    calculate_character_dimensions();
    window.onresize = function() {
      cols = Math.floor(terminalContainer.getBoundingClientRect().width/charWidth);
      rows = Math.floor(terminalContainer.getBoundingClientRect().height/charHeight);
      term.resize(cols, rows);
    }
    window.onresize()
  }
}
