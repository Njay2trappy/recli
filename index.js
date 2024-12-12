const { spawn } = require('child_process');

// Spawn script1.js
const script1 = spawn('node', ['payment_api.js']);
script1.stdout.on('data', (data) => console.log(`Script1 Output: ${data}`));
script1.stderr.on('data', (data) => console.error(`Script1 Error: ${data}`));
script1.on('close', (code) => console.log(`Script1 exited with code ${code}`));

// Spawn script2.js
const script2 = spawn('node', ['users.js']);
script2.stdout.on('data', (data) => console.log(`Script2 Output: ${data}`));
script2.stderr.on('data', (data) => console.error(`Script2 Error: ${data}`));
script2.on('close', (code) => console.log(`Script2 exited with code ${code}`));

