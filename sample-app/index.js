// A trivial Node web app that respects PORT — the Jerrick Cloud deploy contract.
const http = require('http');
const port = process.env.PORT || 3000;
http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<h1>Hello from a Jerrick Cloud app 🚀</h1><p>Served on port ${port} at ${new Date().toISOString()}</p>`);
}).listen(port, () => console.log(`sample-app listening on ${port}`));
