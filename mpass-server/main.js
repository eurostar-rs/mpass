const https = require('https');
const fs = require('fs');
const path = require('path');
const Busboy = require('busboy');
const url = require('url');

const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

const server = https.createServer(options, (req, res) => {
  if (req.url === '/register' && req.method === 'POST') {
    
    console.log('--- Incoming REGISTER Request ---');

    let busboy;
    try {
      // Initialize Busboy with the request headers
      busboy = Busboy({ headers: req.headers });
    } catch (err) {
      console.error('Busboy Init Error:', err);
      res.writeHead(400);
      res.end('Header Error');
      return;
    }

    // 1. Listen for File Uploads
    let isDuplicate = false;

    busboy.on('file', (name, file, info) => {
      const { filename, encoding, mimeType } = info;
      console.log(`File detected! Field: ${name}, File: ${filename}`);


      const savePath = path.join(__dirname, "\\users\\", filename);
      if (fs.existsSync(savePath)) {
        console.log("User already exists. Please login!");

        isDuplicate = true;

        file.resume();
      }
      else {
        const writeStream = fs.createWriteStream(savePath);

        file.pipe(writeStream);

        writeStream.on('finish', () => {
          console.log(`✅ File successfully saved to: ${savePath}`);
        });
    }
    });

    // 2. Listen for Text Fields
    busboy.on('field', (name, val, info) => {
      console.log(`Text Field detected: ${name} = ${val}`);
    });

    // 3. Listen for End of Request
busboy.on('finish', () => {
      console.log('--- Processing Complete ---');
      
      if (isDuplicate) {
        // Send 409 Conflict (Standard HTTP code for "Already Exists")
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          error: 'User already exists', 
          status: 'failed' 
        }));
      } else {
        // Send 200 OK
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          message: 'Registration successful', 
          status: 'success' 
        }));
      }
    });

    // 4. Handle Errors
    busboy.on('error', (err) => {
      console.error('Parse Error:', err);
      res.writeHead(500);
      res.end('Parse Error');
    });

    // PIPE the request into Busboy
    req.pipe(busboy);

  } else if (req.url.startsWith('/login') && req.method == 'GET') {

    console.log('--- Incoming LOGIN Request ---');

    const currentUrl = new URL(req.url, `https://${req.headers.host}`);
    const email = currentUrl.searchParams.get('mail');
  
    if (!email) {
      res.writeHead(400);
      res.end('Email required');
      return;
    }

    console.log(`Login attempt for ${email}`);

    const filename = email.endsWith('.enc') ? email : `${email}.enc`;
    const filePath = path.join(__dirname, 'users', filename);

    if (!fs.existsSync(filePath)) {
      console.log("User doesn't exist. Please register");

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'User not found' }));
      return;
    }
    
    res.writeHead(200, { 'Content-Type' : 'application/octet-stream' });
    const readStream = fs.createReadStream(filePath);
    readStream.pipe(res);
    
  } else if (req.url === '/add' && req.method === 'POST') {
    console.log('--- Incoming ADD ACCOUNT Request ---');

    let busboy;
    try {
      busboy = Busboy({ headers: req.headers });
    } catch (err) {
      console.error('Busboy init error: ', err);
      res.writeHead(400);
      res.end('Header Error');
      return;
    }

    busboy.on('file', (name, file, info) => {
      const {filename, encoding, mimeType} = info;
      console.log(`File detected! Field: ${name}, File: ${filename}`);

      const savePath = path.join(__dirname, "\\users\\", filename);

      const writeStream = fs.createWriteStream(savePath);
      file.pipe(writeStream);

      writeStream.on('finish', () => {
        console.log("File successfully updated");
      })
    })

    busboy.on('finish', () => {
      console.log('--- Add Account Complete ---');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'Account synced successfully' }));
    });

    busboy.on('error', (err) => {
      console.error('Parse Error:', err);
      res.writeHead(500);
      res.end('Parse Error');
    });

    req.pipe(busboy);
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

server.listen(3000, () => {
  console.log('Busboy Server running on https://localhost:3000');
});