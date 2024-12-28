const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const getUserKey = async (req, res) => {
    try {
        // Get token from header
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Find user and get key
        const user = await UserModel.findById(decoded.userId)
            .select('key')
            .lean();

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Convert the stored key to the correct format
        let privateKeyArray;
        
        if (typeof user.key === 'string') {
            // If key is stored as a string of numbers separated by commas
            privateKeyArray = user.key.split(',').map(num => parseInt(num));
        } else if (Array.isArray(user.key)) {
            // If key is stored as an array but needs conversion
            privateKeyArray = user.key.map(num => parseInt(num));
        } else {
            // If key is stored in another format
            throw new Error('Invalid key format');
        }

        // Verify the key array length (should be 64 for ed25519)
        if (privateKeyArray.length !== 64) {
            throw new Error('Invalid key length');
        }

        // Convert to Uint8Array
        const privateKeyUint8 = new Uint8Array(privateKeyArray);
        
        // Create keypair
        const keypair = Keypair.fromSecretKey(privateKeyUint8);

        return res.json({ keypair });

    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        console.error('Error:', error);
        return res.status(500).json({ 
            error: 'Internal server error',
            message: error.message 
        });
    }
};