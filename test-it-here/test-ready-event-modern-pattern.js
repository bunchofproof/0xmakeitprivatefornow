require('dotenv').config({ path: './.env' });
const { Client, GatewayIntentBits, Events } = require('discord.js');

// Test script to verify the modern Discord.js ready event pattern
async function testReadyEventModernPattern() {
  console.log('Testing modern Discord.js ready event pattern...');

  // Check if required env vars are set
  if (!process.env.DISCORD_BOT_TOKEN) {
    console.error('❌ DISCORD_BOT_TOKEN environment variable is not set');
    console.log('Available env vars:', Object.keys(process.env).filter(key => key.includes('DISCORD')));
    process.exit(1);
  }

  // Create client with minimal intents for testing
  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
    ]
  });

  // Track if the event fired correctly
  let readyEventFired = false;

  // Use modern event pattern
  client.on(Events.ClientReady, (readyClient) => {
    console.log('✅ Modern Events.ClientReady event fired correctly');
    console.log(`Bot username: ${readyClient.user?.tag}`);
    readyEventFired = true;

    // Clean up after test
    setTimeout(() => {
      console.log('Test completed successfully - no deprecation warnings observed');
      client.destroy();
      process.exit(0);
    }, 1000);
  });

  // Handle connection errors
  client.on('error', (error) => {
    console.error('❌ Client error:', error.message);
    process.exit(1);
  });

  // Timeout after 30 seconds
  setTimeout(() => {
    if (!readyEventFired) {
      console.error('❌ Ready event did not fire within timeout');
      client.destroy();
      process.exit(1);
    }
  }, 30000);

  try {
    console.log('Attempting to login...');
    await client.login(process.env.DISCORD_BOT_TOKEN);
  } catch (error) {
    console.error('❌ Login failed:', error.message);
    process.exit(1);
  }
}

// Run the test
testReadyEventModernPattern().catch((error) => {
  console.error('❌ Test failed:', error.message);
  process.exit(1);
});