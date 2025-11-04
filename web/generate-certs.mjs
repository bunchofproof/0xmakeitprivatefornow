import selfsigned from 'selfsigned';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🔐 Generating SSL certificates with selfsigned...');

// Generate certificate attributes
const attrs = [
  { name: 'commonName', value: 'localhost' },
  { name: 'organizationName', value: 'ZK Discord Verifier' },
  { name: 'organizationalUnitName', value: 'Development' },
  { name: 'localityName', value: 'Development' },
  { name: 'stateOrProvinceName', value: 'Development' },
  { name: 'countryName', value: 'US' }
];

// Generate certificate extensions for SAN (Subject Alternative Names)
const extensions = [
  {
    name: 'basicConstraints',
    cA: false
  },
  {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true
  },
  {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true
  },
  {
    name: 'subjectAltName',
    altNames: [
      {
        type: 2, // DNS
        value: 'localhost'
      },
      {
        type: 7, // IP
        ip: '127.0.0.1'
      },
      {
        type: 7, // IP
        ip: '192.168.1.8'
      }
    ]
  }
];

try {
  // Generate certificate
  const pems = selfsigned.generate(attrs, {
    keySize: 2048,
    days: 365,
    extensions: extensions,
    pkcs7: false,
    publicKeyAlgorithm: 'rsa',
    hashAlgorithm: 'sha256'
  });

  // Backup existing certificates
  const keyPath = path.join(__dirname, 'localhost-key.pem');
  const certPath = path.join(__dirname, 'localhost.pem');
  
  if (fs.existsSync(keyPath)) {
    fs.renameSync(keyPath, 'localhost-key.pem.backup');
  }
  if (fs.existsSync(certPath)) {
    fs.renameSync(certPath, 'localhost.pem.backup');
  }

  // Write new certificates
  fs.writeFileSync(keyPath, pems.private);
  fs.writeFileSync(certPath, pems.cert);

  console.log('✅ SSL certificates generated successfully!');
  console.log('📁 Files created:');
  console.log('   - localhost-key.pem (Private Key)');
  console.log('   - localhost.pem (Certificate)');
  console.log('📋 Certificate details:');
  console.log(`   - Subject CN: localhost`);
  console.log(`   - Organization: ${attrs.find(a => a.name === 'organizationName').value}`);
  console.log(`   - Valid for: 365 days`);
  console.log(`   - Key Size: 2048 bits`);
  console.log(`   - Hash Algorithm: SHA-256`);
  console.log('🌐 Subject Alternative Names:');
  console.log('   - DNS: localhost');
  console.log('   - IP: 127.0.0.1');
  console.log('   - IP: 192.168.1.8');
} catch (error) {
  console.error('❌ Error generating certificates:', error);
  process.exit(1);
}