/* glossary.js — the vocabulary. Used by term hovers and by the Model's vocabulary section. */
(function () {
  const term = window.TDS.term;

  term('connection', 'One TCP link to the server, with its own login, transaction and settings. A session lives exactly as long as its connection.');
  term('serial channel', 'An ordered path that carries one exchange at a time. A connection has one, or several with MARS, which take turns on the server.');
  term('exchange', 'One request and its complete response.');
  term('packet', 'The unit written to the wire. It is an 8-byte header plus up to (packet size − 8) bytes of payload.');
  term('packet size', 'The largest packet allowed. It is 4096 until the server announces another value during login.');
  term('message', 'One complete thing that one side sends, such as a login, a query or a result. It spans one or more packets.');
  term('body', "A message's content once its packets are joined.");
  term('structure', 'A body with a fixed layout determined by the message type, such as PRELOGIN or LOGIN7.');
  term('token stream', 'A body made of tokens, one after another, with no separators.');
  term('token', "A 1-byte tag followed by that tag's fields. Examples are LOGINACK, ENVCHANGE and DONE.");
  term('result set', 'Columns, then rows, inside a response. COLMETADATA opens it, and the next completion closes it.');
  term('completion', 'A DONE, DONEINPROC or DONEPROC token. It reports that a statement or procedure call ended, with its row count when the server sends one.');
  term('field', 'A named, typed value inside a structure or token.');
  term('conversation', 'The ordered sequence of messages between client and server: first connecting, then requests.');
  term('step', 'One named stage of a conversation, such as hello, secure, log in or ready.');
  term('session state', 'What the client knows about the session: its database, language, packet size, collation and transaction. Only announcements change it.');
  term('announcement', 'An ENVCHANGE token. The server sends it to tell the client that a session setting changed.');
  term('MARS', 'Multiple Active Result Sets. It is a framing layer that lets one connection carry several serial channels. The channels take turns on the server, so MARS does not add parallelism.');
  term('pool', 'A set of connections. Each one is lent, whole, to one borrower at a time, and is reset when it is returned.');
  term('connection manager', 'The single component that sets up connections (TCP, TLS, hello, login and MARS). It owns everything that serial channels share.');
  term('owner', 'The task or thread that opened a serial channel. Only the owner may send and read on it.');
})();
