import express from 'express';
import http from 'http';
import https from 'https';
import { readdirSync, readFileSync, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import logger from './modules/logger.js';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config({ quiet: true });

const PORT = process.env.PORT || 3001;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || path.resolve(__dirname, 'certs', 'localhost.key');
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || path.resolve(__dirname, 'certs', 'localhost.crt');
const ENABLE_HTTPS = process.env.HTTPS === 'true';

const app = express();
// Allow connections from any origin for network access
app.use(cors({
  origin: (origin, callback) => {
    // Allow any origin for network access (you can restrict this later for security)
    callback(null, true);
  },
  methods: ['GET', 'POST'],
  credentials: true,
}));

// Create HTTP or HTTPS server depending on env/cert availability
let isHttps = false;
let server;
if (ENABLE_HTTPS && (existsSync(SSL_KEY_PATH) && existsSync(SSL_CERT_PATH))) {
  const key = readFileSync(SSL_KEY_PATH);
  const cert = readFileSync(SSL_CERT_PATH);
  server = https.createServer({ key, cert }, app);
  isHttps = true;
} else {
  server = http.createServer(app);
}

const wss = new WebSocketServer({ noServer: true });

const routeHandlers = {};

const routeFiles = readdirSync('./routes').filter(file => file.endsWith('.js'));

for (const file of routeFiles) {
  const routePath = '/' + file.replace('.js', '');
  const module = await import(`./routes/${file}`);
  app.get(routePath + '/init', module.init);
  routeHandlers[routePath] = module.wsHandler;
  logger.info(`🧩 Loaded route ${routePath}`);
}

server.on('upgrade', (req, socket, head) => {
  const scheme = isHttps ? 'https' : 'http';
  const url = new URL(req.url, `${scheme}://${req.headers.host}`);
  const route = url.pathname;

  const handler = routeHandlers[route];
  if (handler) {
    wss.handleUpgrade(req, socket, head, (ws) => {
      handler(ws, req);
    });
  } else {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
  }
});

server.listen(PORT, '0.0.0.0', () => {
  const scheme = isHttps ? 'https' : 'http';
  console.log(`🚀 Auth server running at ${scheme}://0.0.0.0:${PORT}`);
  console.log(`🌐 Server accessible from network at ${scheme}://[your-ip]:${PORT}`);
});
