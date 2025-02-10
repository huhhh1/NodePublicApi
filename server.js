const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// Configuration matching Salesforce implementation
const TRANSMISSION_SYMMETRIC_KEY = 'ejZ2OXkkQiZFKUhATWNRZlRqV25acjR1N3ghQSVEKkc=';
const CRYPTO_ALGORITHM = 'aes-256-cbc'; // AES256 in OpenSSL terms is aes-256-cbc

// Helper function to validate key length
function validateKey(key) {
    const keyBuffer = Buffer.from(key, 'base64');
    if (keyBuffer.length !== 32) {
        throw new Error('Invalid key size - must be 32 bytes');
    }
    return keyBuffer;
}

// Encryption endpoint
app.post('/encrypt', (req, res) => {
    try {
        const { plainText, encryptionKey = TRANSMISSION_SYMMETRIC_KEY } = req.body;

        if (!plainText) {
            return res.status(400).json({ error: 'Missing plainText parameter' });
        }

        const key = validateKey(encryptionKey);
        const iv = crypto.randomBytes(16); // 16-byte IV for AES-CBC

        const cipher = crypto.createCipheriv(CRYPTO_ALGORITHM, key, iv);
        let encrypted = cipher.update(plainText, 'utf8', 'binary');
        encrypted += cipher.final('binary');

        // Combine IV and encrypted data
        const combined = Buffer.concat([iv, Buffer.from(encrypted, 'binary')]);
        const encryptedData = combined.toString('base64');

        res.json({ encryptedData });

    } catch (error) {
        res.status(500).json({ error: `Encryption failed: ${error.message}` });
    }
});

// Decryption endpoint
app.post('/decrypt', (req, res) => {
    try {
        const { encryptedData, encryptionKey = TRANSMISSION_SYMMETRIC_KEY } = req.body;

        if (!encryptedData) {
            return res.status(400).json({ error: 'Missing encryptedData parameter' });
        }

        const key = validateKey(encryptionKey);
        const combined = Buffer.from(encryptedData, 'base64');

        // Extract IV (first 16 bytes) and encrypted data
        const iv = combined.slice(0, 16);
        const encrypted = combined.slice(16);

        const decipher = crypto.createDecipheriv(CRYPTO_ALGORITHM, key, iv);
        let decrypted = decipher.update(encrypted.toString('binary'), 'binary', 'utf8');
        decrypted += decipher.final('utf8');

        res.json({ decryptedData: decrypted });

    } catch (error) {
        res.status(500).json({ error: `Decryption failed: ${error.message}` });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Secure transmission server running on port ${PORT}`);
});