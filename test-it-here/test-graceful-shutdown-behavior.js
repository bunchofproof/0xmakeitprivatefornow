// Test script to verify graceful shutdown behavior
// This script tests that the bot properly handles SIGINT and SIGTERM signals
// and closes the database connection during shutdown

const { spawn } = require('child_process');
const path = require('path');

async function testGracefulShutdown() {
    console.log('Testing graceful shutdown behavior...');

    // Start the bot process
    const botProcess = spawn('node', ['--loader', 'ts-node/esm', 'src/index.ts'], {
        cwd: path.join(__dirname, '../bot'),
        stdio: 'pipe'
    });

    let output = '';
    let startupComplete = false;

    // Collect output
    botProcess.stdout.on('data', (data) => {
        const str = data.toString();
        output += str;
        console.log('BOT OUTPUT:', str.trim());

        if (str.includes('Bot logged in successfully') && !startupComplete) {
            startupComplete = true;
            console.log('Bot startup complete, sending SIGINT...');

            // Send SIGINT after a short delay to simulate graceful shutdown
            setTimeout(() => {
                botProcess.kill('SIGINT');
            }, 1000);
        }
    });

    botProcess.stderr.on('data', (data) => {
        console.log('BOT ERROR:', data.toString().trim());
    });

    return new Promise((resolve, reject) => {
        botProcess.on('close', (code, signal) => {
            console.log(`Bot process closed with code ${code} and signal ${signal}`);

            // Verify graceful shutdown messages
            const hasGracefulShutdownMessage = output.includes('Graceful shutdown initiated. Closing database connection');
            const hasDatabaseDisconnectMessage = output.includes('Prisma database connection closed') ||
                                               output.includes('JSON database driver disconnected');
            const hasShutdownCompletedMessage = output.includes('Graceful shutdown completed');

            console.log('Verification results:');
            console.log('- Graceful shutdown initiated:', hasGracefulShutdownMessage ? 'PASS' : 'FAIL');
            console.log('- Database disconnect message:', hasDatabaseDisconnectMessage ? 'PASS' : 'FAIL');
            console.log('- Shutdown completed message:', hasShutdownCompletedMessage ? 'PASS' : 'FAIL');

            const success = hasGracefulShutdownMessage && hasDatabaseDisconnectMessage && hasShutdownCompletedMessage;

            if (success) {
                console.log('✅ Graceful shutdown test PASSED');
                resolve(true);
            } else {
                console.log('❌ Graceful shutdown test FAILED');
                reject(new Error('Graceful shutdown verification failed'));
            }
        });

        botProcess.on('error', (error) => {
            console.error('Process error:', error);
            reject(error);
        });

        // Timeout after 30 seconds
        setTimeout(() => {
            console.log('Test timeout - killing process');
            botProcess.kill('SIGKILL');
            reject(new Error('Test timed out'));
        }, 30000);
    });
}

testGracefulShutdown().catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
});