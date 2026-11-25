// ---- TEMPORARY DEBUG: shows every listen() call and where it comes from ----
const net = require('net');
const origListen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  console.log('LISTEN CALLED with', JSON.stringify(args[0]), '\n', new Error().stack);
  return origListen.apply(this, args);
};
// ---- END DEBUG ----

const app = require('./app');

const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, '0.0.0.0');

server.on('listening', () => {
  console.log(`IRMS Backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  if (!process.env.GEMINI_API_KEY && !process.env.OPENAI_API_KEY) {
    console.log('AI Mode: Enterprise Cognitive Defense Engine Active');
  } else {
    console.log('AI Mode: Live Cloud AI Active');
  }
});

server.on('error', (err) => {
  console.error('LISTEN ERROR', err);
  process.exit(1);
});