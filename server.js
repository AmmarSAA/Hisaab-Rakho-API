// Retire the unauthenticated JSON Server, including old Vercel deployments.
// Financial records are available only from the private Worker API after login.
const http = require('node:http');
const handler = (_request, response) => {
  response.writeHead(410, {'Content-Type':'application/json','Cache-Control':'no-store'});
  response.end(JSON.stringify({error:'Legacy API retired. Use the authenticated private API.'}));
};
if (require.main === module) http.createServer(handler).listen(process.env.PORT || 3000);
module.exports = handler;
