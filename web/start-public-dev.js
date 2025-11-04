#!/usr/bin/env node

import { spawn } from 'child_process';
import { exec } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const webDir = join(__dirname);

console.log('🚀 Starting ZK Discord Verifier with Public Access');
console.log('📱 This will create a public URL for your phone to access!');
console.log(`📁 Working directory: ${webDir}`);

// Start the HTTPS server
console.log('\n🔐 Starting HTTPS server...');
const httpsServer = spawn('npm', ['run', 'dev:https'], {
  cwd: webDir,
  env: { ...process.env },
  stdio: 'pipe'
});

httpsServer.stdout.on('data', (data) => {
  console.log('📋 HTTPS Server:', data.toString().trim());
});

httpsServer.stderr.on('data', (data) => {
  console.error('❌ HTTPS Server Error:', data.toString().trim());
});

// Wait a bit for the server to start, then start ngrok
setTimeout(() => {
  console.log('\n🌐 Starting ngrok tunnel...');
  console.log('⏳ This will create a public URL for your phone...');
  
  const ngrok = spawn('npx', ['ngrok', 'http', '3000'], {
    cwd: webDir,
    env: { ...process.env },
    stdio: 'pipe'
  });

  let ngrokReady = false;

  ngrok.stdout.on('data', (data) => {
    const output = data.toString();
    console.log('📋 ngrok:', output.trim());
    
    // Check if ngrok has started successfully
    if (output.includes('started tunnel') || output.includes('Forwarding')) {
      if (!ngrokReady) {
        ngrokReady = true;
        console.log('\n🎉 SUCCESS! Your phone can now access the app!');
        console.log('📱 Look for the URL in the output above (like https://xxx.ngrok.io)');
        console.log('🔗 Copy that URL and use it in your zkpassport app');
        console.log('\n⚡ Quick setup for your phone:');
        console.log('1. Open your zkpassport app');
        console.log('2. Scan QR code or enter the URL');
        console.log('3. Complete the verification process');
        console.log('\n🛑 To stop: Press Ctrl+C in this terminal');
      }
    }
  });

  ngrok.stderr.on('data', (data) => {
    console.error('❌ ngrok Error:', data.toString().trim());
  });

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down servers...');
    httpsServer.kill('SIGTERM');
    ngrok.kill('SIGTERM');
    process.exit(0);
  });

}, 3000);

// Error handling
httpsServer.on('error', (error) => {
  console.error('❌ Failed to start HTTPS server:', error);
  process.exit(1);
});

console.log('\n📋 Instructions:');
console.log('1. Wait for ngrok to generate a public URL');
console.log('2. Copy the HTTPS URL (looks like: https://abc123.ngrok.io)');
console.log('3. Use that URL in your zkpassport app on your phone');
console.log('4. The green padlock shows secure connection ✅');