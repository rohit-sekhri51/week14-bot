require("dotenv").config();

const { Keypair, Transaction, sendAndConfirmTransaction, Connection } = require("@solana/web3.js");
const {UserModel} = require("./mongoDB");       // Destructing
const jwt = require("jsonwebtoken");
const express = require("express");
const mongoose = require("mongoose");

const bs58 = require("bs58");
const cors = require("cors");

const JWT_SECRET = "ILoveGNT";
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect("mongodb+srv://rohitsekhri51:dw7XFXrvwXbqHf7J@cluster0.fb4al.mongodb.net/week-14");

const connection = new Connection("https://devnet.helius-rpc.com/?api-key=0da89612-6136-410f-8718-66f8e4b35d33");

app.post("/api/vi/signup",async (req, res) => {

    const username = req.body.username;
    const password = req.body.password;
    // validate inputs zod, hash the password

    try {
    const payer = new Keypair();

    // check if user already present in DB

    const secretKeyArray = Array.from(payer.secretKey);

    console.log('Secret key type:', typeof secretKeyArray);
    // Validate secret key format
    if (!secretKeyArray || !Array.isArray(secretKeyArray) || secretKeyArray.length !== 64) {
        throw new Error(`Invalid secret key format. Length: ${secretKeyArray?.length}`);
    }
    
    const newUser = await UserModel.create({
        username,
        password,
        privateKey: secretKeyArray,
        publicKey: payer.publicKey.toString()
    });
    console.log('User created successfully:', newUser);

    res.json({
        message: payer.publicKey.toString()
    });
    } catch(error){
        res.status(401).json({
            message: "User already exists"
        });

        if (error.code === 11000) {
            throw new Error('Username already exists');
        }
        if (error.name === 'ValidationError') {
            const validationErrors = Object.values(error.errors).map(err => err.message);
            throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
        }
        console.error('Error creating user:', error);
        throw error;
    }
});

app.post("/api/vi/signin",async (req, res) => {

    const username = req.body.username;
    const password = req.body.password;

    const userValid = await UserModel.findOne({
        username: username,
        password: password
    });
    console.log("userValid is: " + userValid );

    if(userValid) {
        // jwt
        const token = jwt.sign({
            id: userValid._id           
        }, JWT_SECRET, { expiresIn: '24h' } );

        res.json({
            token
        });
        console.log("Jwt is: " + JSON.stringify(token));

    } else {
        res.status(403).json({
            message: "Incorrect credentails"
        });
    }

    // res.json({
    //     message: "Sign In"
    // });
});

app.post("/api/vi/txn/sign",async (req, res) => {

    // Verify JWT
    // const token = req.headers.authorization;
    const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

    const response = jwt.verify(token, JWT_SECRET);
console.log("jwt verify response is: " + JSON.stringify(response));
    req.userId = response.id;

    const serialiseTx = req.body.message;
// console.log("serialiseTx: " + JSON.stringify(serialiseTx));

    const tx = Transaction.from(Buffer.from(serialiseTx));

    // const user = await UserModel.find({
    //         _id: req.userId
    //          }).limit(1);

    // If req.userId is a string, convert it to ObjectId
    const objectId = new mongoose.Types.ObjectId(req.userId);
    // Validate if ID is in correct format
    if (!mongoose.Types.ObjectId.isValid(objectId)) {
        return res.status(400).json({ error: 'Invalid user ID format' });
    }

        // Find user and get key
        const user = await UserModel.findById(objectId)
        .select('privateKey')
        .lean();        // Convert to plain JavaScript object

        if (!user) {
        return res.status(402).json({ error: 'User not found' });
        }

        const privateKey = user.privateKey;

        // Convert the stored key to the correct format
        let privateKeyArray;
        
        if (typeof privateKey === 'string') {
            // If key is stored as a string of numbers separated by commas
            privateKeyArray = privateKey.split(',').map(num => parseInt(num));
        } else if (Array.isArray(privateKey)) {
            // If key is stored as an array but needs conversion
            privateKeyArray = privateKey.map(num => parseInt(num));
        } else {
            // If key is stored in another format
            throw new Error('Invalid key format');
        }

        // Verify the key array length (should be 64 for ed25519)
        if (privateKeyArray.length !== 64) {
            throw new Error('Invalid key length');
        }

console.log("Secret Key is: " + privateKeyArray );

//console.log(bs58);
    // Create keypair from Uint8Array secret key
    const keypair = Keypair.fromSecretKey(Uint8Array.from(privateKeyArray));
    // const keypair = Keypair.fromSecretKey(bs58.default.decode(privateKey));     // (Uint8Array.from(process.env.PRIVATE_KEY)); 
// console.log("Afer Keypair");

    // tx.sign(keypair);
    const txHash = await connection.sendTransaction(tx,[keypair]);
    console.log("Tx Hash is: "+ txHash );

    res.json({
        message: txHash
        //name: user.username
    });
});

app.post("/api/vi/txn",async (req, res) => {

    try {
    const txHash = req.body.message;
    console.log("Tx Hash is: "+ txHash );

    // Check if signature meets base58 requirements
    if (!/^[1-9A-HJ-NP-Za-km-z]{87,88}$/.test(txHash)) {
        throw new Error('Invalid signature format. Must be 87-88 characters in base58.');
      }

    const status = await connection.getSignatureStatus(txHash,{
        searchTransactionHistory: true
    });

    if (!status || !status.value) {
        throw new Error('Signature not found');
      }

    console.log("Status is: "+ status.value.confirmationStatus );
    res.json({
        message: status.value.confirmationStatus
    });

    } catch (error) {
        if (error.message.includes('WrongSize')) {
        throw new Error('Invalid signature length or format');
        }
        throw error;
    }
    
});

app.listen(3000);
console.log("Listening on Port 3000");