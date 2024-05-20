import express from 'express';
import https from 'https';
import fs from 'fs';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

app.use(express.static(__dirname));

app.use('/api', createProxyMiddleware({
  target: '$domain',
  changeOrigin: true,
  secure: true,
  pathRewrite: { '^/api': '/DH' },
}));

const options = {
  key: fs.readFileSync('ssl/key.pem'),
  cert: fs.readFileSync('ssl/cert.pem'),
};

https.createServer(options, app).listen(3000, () => {
  console.log('HTTPS server and proxy running on https://localhost:3000');
});
