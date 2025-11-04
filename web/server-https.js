import { createServer } from 'https';
import { readFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';
import { request } from 'http';

const __filename = fileURLToPath(import.meta.url);
const __dirname = join(__filename, '..');

console.log('🔐 Starting HTTPS Next.js development server...');

// Check if certificate files exist
const keyPath = join(__dirname, 'localhost-key.pem');
const certPath = join(__dirname, 'localhost.pem');

try {
  const key = readFileSync(keyPath, 'utf8');
  const cert = readFileSync(certPath, 'utf8');

  const httpsOptions = {
    key,
    cert
  };

  console.log('✅ SSL certificates loaded successfully');
  console.log('🌐 Starting HTTPS server...');
  console.log('📱 Local:  https://localhost:3000');
  console.log('🌍 Network: https://192.168.1.8:3000');
  console.log('⏳ Starting Next.js server...');

  // Start the custom HTTPS server
  const server = createServer(httpsOptions, (req, res) => {
    // Proxy requests to Next.js dev server (which runs on HTTP port 3001)
    const options = {
      hostname: 'localhost',
      port: 3001,
      path: req.url,
      method: req.method,
      headers: req.headers
    };

    const proxyReq = request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res, { end: true });
    });

    proxyReq.on('error', (err) => {
      console.error('❌ Proxy error:', err);
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Bad Gateway');
    });

    req.pipe(proxyReq, { end: true });
  });

  server.listen(3000, '0.0.0.0', () => {
    console.log('🚀 HTTPS server listening on port 3000');
  });

  // Start Next.js on HTTP port 3001 in the background
  console.log('📦 Starting Next.js development server...');
  const nextProcess = exec('npm run dev:next', {
    cwd: __dirname,
    env: { ...process.env, PORT: '3001' }
  }, (error, stdout, stderr) => {
    if (error) {
      console.error('❌ Next.js process error:', error);
    }
  });

  nextProcess.stdout?.on('data', (data) => {
    const output = data.toString();
    if (output.includes('Ready in') || output.includes('Compiled')) {
      console.log('📋 Next.js:', output.trim());
    }
  });

  nextProcess.stderr?.on('data', (data) => {
    console.error('📋 Next.js stderr:', data.toString().trim());
  });

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down servers...');
    server.close();
    nextProcess.kill('SIGINT');
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log('\n🛑 Shutting down servers...');
    server.close();
    nextProcess.kill('SIGTERM');
    process.exit(0);
  });

} catch (error) {
  console.error('❌ Error loading SSL certificates:', error.message);
  console.log('🔧 Make sure to run: node generate-certs.mjs');
  process.exit(1);
}