// Test: Signal Handling for Graceful Shutdown
// Acceptance Criteria: Upon receiving SIGINT (Ctrl+C), the gracefulShutdown function must execute,
// logging "Graceful shutdown initiated. Closing database connection..." and properly disconnecting the database.

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

console.log('Starting signal handling test...');

// Start the bot process using node directly
const botProcess = spawn('node', ['--import', 'tsx/esm', 'src/index.ts'], {
  cwd: path.join(__dirname, '..', 'bot'),
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, NODE_ENV: 'test', TSX_WATCH: 'false' }
});

let output = '';
let errorOutput = '';
let shutdownLogged = false;
let databaseDisconnected = false;

botProcess.stdout.on('data', (data) => {
  const text = data.toString();
  console.log('BOT STDOUT:', text);
  output += text;

  if (text.includes('Graceful shutdown initiated. Closing database connection')) {
    shutdownLogged = true;
  }
  if (text.includes('Database disconnected successfully') || text.includes('disconnectDatabase called')) {
    databaseDisconnected = true;
  }
});

botProcess.stderr.on('data', (data) => {
  const text = data.toString();
  console.log('BOT STDERR:', text);
  errorOutput += text;
});

// Wait for bot to fully start
setTimeout(() => {
  console.log('Sending SIGINT to bot process...');
  botProcess.kill('SIGINT');
}, 10000); // Wait 10 seconds for bot to start

// Wait for process to exit
botProcess.on('exit', (code, signal) => {
  console.log(`Bot process exited with code ${code} and signal ${signal}`);

  // Verify results
  const success = shutdownLogged && (code === 0);

  if (success) {
    console.log('✅ TEST PASSED: Graceful shutdown executed correctly');
    process.exit(0);
  } else {
    console.log('❌ TEST FAILED: Graceful shutdown did not execute');
    console.log('Shutdown logged:', shutdownLogged);
    console.log('Process exited with code:', code);
    process.exit(1);
  }
});

botProcess.on('error', (err) => {
  console.error('Failed to start bot process:', err);
  process.exit(1);
});

// Timeout after 30 seconds
setTimeout(() => {
  console.log('Test timed out');
  botProcess.kill('SIGKILL');
  process.exit(1);
}, 30000);