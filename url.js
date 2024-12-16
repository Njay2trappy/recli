const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const Web3 = require('web3');
const { Keypair, Connection, clusterApiUrl, SystemProgram, Transaction, PublicKey } = require('@solana/web3.js');
const axios = require('axios');
const TonWeb = require('tonweb');
const { ethers } = require('ethers');

// File paths for JSON storage
const paymentsFilePath = path.join(__dirname, 'payments.json');

// Admin Wallets
const BSC_ADMIN_WALLET = "0x15Dc6AB3B9b45821d6c918Ec1b256F6f7470E4DC";
const SOLANA_ADMIN_WALLET = "B6ze7uHAdKeXucs3uguYKbcGeeiz3pzizdLbz3rPembe";
const BSC_TESTNET_RPC = "https://data-seed-prebsc-1-s1.binance.org:8545";

// TON testnet configuration
const tonweb = new TonWeb(new TonWeb.HttpProvider('https://testnet.toncenter.com/api/v2/jsonRPC', {
    apiKey: '8723f42a9a980ba38692832aad3d42fcbe0f0435600c6cd03d403e800bdd2e88',
}));

// Initialize Web3 for BSC
const web3 = new Web3(BSC_TESTNET_RPC);

// Initialize Solana Connection
const solanaConnection = new Connection(clusterApiUrl('devnet'));

const loadFromFile = (filename) => {
    if (!fs.existsSync(filename)) {
        console.warn(`${filename} not found, initializing with an empty array.`);
        return [];
    }
    try {
        return JSON.parse(fs.readFileSync(filename, 'utf8'));
    } catch (error) {
        console.error(`Error reading or parsing ${filename}:`, error.message);
        return [];
    }
};

const saveToFile = (filename, data) => {
    fs.writeFileSync(filename, JSON.stringify(data, null, 2));
};

const apikeysFilePath = path.join(__dirname, 'apikeys.json');

const fetchLivePrice = async (blockchain) => {
    try {
        if (blockchain === 'AMB') {
            // Fetch AirDAO (AMB) price using CryptoRank API
            const response = await axios.get('https://api.cryptorank.io/v0/coins/prices', {
                params: {
                    keys: 'airdao', // Coin key for AirDAO (AMB)
                    currency: 'USD' // Fetch price in USD
                }
            });

            // Extract price from the response
            const ambData = response.data.data.find(item => item.key === 'airdao');
            if (ambData && ambData.price) {
                return ambData.price; // Return the current price in USD
            } else {
                throw new Error('AMB price data is missing from the API response.');
            }
        } else if (blockchain === 'BSC') {
            const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
                params: { ids: 'binancecoin', vs_currencies: 'usd' }
            });
            return response.data.binancecoin.usd;
        } else if (blockchain === 'Solana') {
            const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
                params: { ids: 'solana', vs_currencies: 'usd' }
            });
            return response.data.solana.usd;
        } else if (blockchain === 'TON') {
            const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
                params: { ids: 'the-open-network', vs_currencies: 'usd' }
            });
            return response.data['the-open-network'].usd;
        }
        throw new Error('Unsupported blockchain');
    } catch (error) {
        console.error(`Error fetching live price for ${blockchain}:`, error.message);
        throw new Error('Failed to fetch live price');
    }
};

const validateWalletAddress = (address, blockchain) => {
    if (blockchain === 'BSC') {
        return web3.utils.isAddress(address); // BSC validation using Web3.js
    } else if (blockchain === 'Solana') {
        try {
            new PublicKey(address); // Throws an error if the address is invalid
            return true;
        } catch (error) {
            return false;
        }
    } else if (blockchain === 'TON') {
        try {
            // Validate TON wallet address in UQ format
            const tonUQRegex = /^[UQ][A-Za-z0-9_-]{47}$/; // Example regex for UQ address format
            return tonUQRegex.test(address);
        } catch (error) {
            return false;
        }
    } else if (blockchain === 'AMB') {
        try {
            // Validate AMB wallet address
            return ethers.isAddress(address); // AMB validation using Ethers.js
        } catch (error) {
            return false;
        }
    }
    throw new Error('Unsupported blockchain');
};

// GraphQL Schema
const typeDefs = gql`
    type Query {
        getPayment(adminToken: String!): [Payment]
        getPaymentsByUser(userToken: String, apiKey: String): [Payment]
    }
    type Mutation {
    generatePaymentAddress(
        apiKey: String!
        amount: Float!
        blockchain: String!
        recipientAddress: String!
    ): Payment
    }
    type Payment {
    id: ID!
    walletAddress: String!
    privateKey: String!
    recipientAddress: String!
    amount: Float!
    status: String!
    createdAt: String!
    blockchain: String!
    convertedAmount: Float!
    }
`;

const createPaymentId = () => {
    const uuid = uuidv4().replace(/-/g, ''); // Remove dashes from UUID
    const suffix = "Order"; // Static or dynamic suffix
    const id = Buffer.from(`${uuid}:${suffix}`).toString('base64'); // Encode in Base64
    return id;
};

// GraphQL Resolvers
const resolvers = {
    Query: {
        getPayment: (_, { adminToken, superKey }) => {
            // Load payments dynamically
            const payments = loadFromFile(paymentsFilePath);
        
            // Check for admin token
            if (adminToken) {
                const adminTokens = loadFromFile(path.join(__dirname, 'adtokens.json'));
                if (!adminTokens.includes(adminToken)) {
                    throw new Error('Invalid or unauthorized admin token');
                }
            }
            // Check for Super Key
            else if (superKey) {
                const superKeys = loadFromFile(path.join(__dirname, 'superkeys.json'));
                const validSuperKey = superKeys.find(key => key.apiKey === superKey);
                if (!validSuperKey) {
                    throw new Error('Invalid or unauthorized Super Key');
                }
            } else {
                throw new Error('Either an admin token or a Super Key is required');
            }
        
            // Return all payments
            return payments;
        },        
        getPaymentsByUser: (_, { userToken, apiKey }) => {
            // Load payments dynamically
            const payments = loadFromFile(paymentsFilePath);
        
            let email;
        
            // Validate user token
            if (userToken) {
                const userTokens = loadFromFile(path.join(__dirname, 'tokens.json'));
                const validUser = userTokens.find(token => token.token === userToken);
                if (!validUser) {
                    throw new Error('Invalid or unauthorized user token');
                }
                email = validUser.email; // Extract email from userToken entry
            }
            // Validate API key
            else if (apiKey) {
                const apiKeys = loadFromFile(path.join(__dirname, 'apikeys.json'));
                const validApiKey = apiKeys.find(key => key.apiKey === apiKey);
                if (!validApiKey) {
                    throw new Error('Invalid or unauthorized API key');
                }
                email = validApiKey.userData?.email; // Extract email from userData in API key entry
            } else {
                throw new Error('Either a valid user token or API key is required');
            }
        
            // Filter payments by email
            return payments.filter(payment => payment.email === email);
        },        
    },
    Mutation: {
        generatePaymentAddress: async (_, { apiKey, amount, blockchain, recipientAddress }) => {
            // Load API keys dynamically
            const apiKeys = loadFromFile(path.join(__dirname, 'apikeys.json'));
        
            // Validate the provided API key
            const apiKeyEntry = apiKeys.find((key) => key.apiKey === apiKey);
            if (!apiKeyEntry) {
                throw new Error('Invalid or unauthorized API Key');
            }
        
            // Extract email from user data
            const userEmail = apiKeyEntry.userData?.email;
            if (!userEmail) {
                throw new Error('Email not found for the provided API Key');
            }
        
            // Validate deposit amount
            if (amount <= 0) {
                throw new Error('Amount must be greater than 0');
            }
        
            // Validate recipient wallet address
            if (!validateWalletAddress(recipientAddress, blockchain)) {
                throw new Error(`Invalid recipient address for blockchain: ${blockchain}`);
            }
        
            let walletAddress, privateKey, convertedAmount;
        
            if (blockchain === 'AMB') {
                // Generate AMB wallet
                const wallet = ethers.Wallet.createRandom();
                walletAddress = wallet.address;
                privateKey = wallet.privateKey;
        
                // Fetch live price for AMB and calculate converted amount
                const livePrice = await fetchLivePrice(blockchain);
                convertedAmount = amount / livePrice;
        
            } else if (blockchain === 'BSC') {
                // Generate BSC wallet
                const account = web3.eth.accounts.create();
                walletAddress = account.address;
                privateKey = account.privateKey;
        
                // Fetch live price for BSC and calculate converted amount
                const livePrice = await fetchLivePrice(blockchain);
                convertedAmount = amount / livePrice;
        
            } else if (blockchain === 'Solana') {
                // Generate Solana wallet
                const keypair = Keypair.generate();
                walletAddress = keypair.publicKey.toBase58();
                privateKey = Buffer.from(keypair.secretKey).toString('hex');
        
                // Fetch live price for Solana and calculate converted amount
                const livePrice = await fetchLivePrice(blockchain);
                convertedAmount = amount / livePrice;
        
            } else if (blockchain === 'TON') {
                // Generate TON wallet
                const keyPair = TonWeb.utils.newKeyPair();
                const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, { publicKey: keyPair.publicKey, wc: 0 });
                walletAddress = (await wallet.getAddress()).toString(true, true, false); // UQ format
                privateKey = TonWeb.utils.bytesToHex(keyPair.secretKey);
        
                // Fetch live price for TON and calculate converted amount
                const livePrice = await fetchLivePrice(blockchain);
                convertedAmount = amount / livePrice;
        
            } else {
                throw new Error('Unsupported blockchain');
            }
        
            // Create a new payment record
            const newPayment = {
                id: createPaymentId(),
                email: userEmail,
                walletAddress,
                privateKey,
                recipientAddress,
                amount,
                convertedAmount,
                status: 'Pending',
                createdAt: new Date().toISOString(),
                blockchain,
            };
        
            // Save the payment record in payments.json
            const payments = loadFromFile(paymentsFilePath);
            payments.push(newPayment);
            saveToFile(paymentsFilePath, payments);
        
            // Monitor the payment for completion
            monitorPayment(newPayment);
        
            return newPayment;
        },        
         
    },
};

const monitorPayment = async (payment) => {
    const { walletAddress, privateKey, recipientAddress, blockchain, convertedAmount } = payment;
    const endTime = Date.now() + 10 * 60 * 1000; // 10 minutes from now

    const interval = setInterval(async () => {
        if (Date.now() >= endTime) {
            clearInterval(interval);
            updatePaymentStatus(payment.id, 'Cancelled');
            console.log(`Payment monitoring timed out for wallet ${walletAddress}`);
            return;
        }

        try {
            if (blockchain === 'BSC') {
                const balance = await web3.eth.getBalance(walletAddress);
                if (parseFloat(web3.utils.fromWei(balance, 'ether')) >= convertedAmount) {
                    clearInterval(interval);
                    await transferBSCFunds(walletAddress, privateKey, recipientAddress, balance);
                    updatePaymentStatus(payment.id, 'Completed');
                    console.log(`Payment completed for BSC wallet ${walletAddress}`);
                }
            } else if (blockchain === 'Solana') {
                const publicKey = new PublicKey(walletAddress);
                const balance = await solanaConnection.getBalance(publicKey);
                if (balance >= convertedAmount * 1e9) { // Converted amount to lamports
                    clearInterval(interval);
                    await transferSolanaFunds(walletAddress, privateKey, recipientAddress, balance);
                    updatePaymentStatus(payment.id, 'Completed');
                    console.log(`Payment completed for Solana wallet ${walletAddress}`);
                }
            } else if (blockchain === 'TON') {
                const balance = await tonweb.provider.getBalance(walletAddress);
                if (balance >= convertedAmount * 1e9) { // Converted amount to nanotons
                    clearInterval(interval);
                    await transferTONFunds(walletAddress, privateKey, recipientAddress, balance);
                    updatePaymentStatus(payment.id, 'Completed');
                    console.log(`Payment completed for TON wallet ${walletAddress}`);
                }
            } else if (blockchain === 'AMB') {
                const balance = await provider.getBalance(walletAddress);
                const balanceInEther = parseFloat(ethers.formatEther(balance));
                if (balanceInEther >= convertedAmount) {
                    clearInterval(interval);
                    await transferAMBFunds(balanceInEther, privateKey, recipientAddress); 
                    updatePaymentStatus(payment.id, 'Completed');
                    console.log(`Payment completed for AMB wallet ${walletAddress}`);
                }
            }
            
        } catch (error) {
            console.error(`Error monitoring payment for wallet ${walletAddress}:`, error.message);
            clearInterval(interval); // Ensure interval is cleared on error
        }
    }, 2000); // Check every 2 seconds
};

const transferBSCFunds = async (walletAddress, privateKey, recipientAddress, balance) => {
    try {
        const gasPrice = await web3.eth.getGasPrice();
        const gasLimit = 21000;

        const txCost = BigInt(gasPrice) * BigInt(gasLimit);
        const transferableBalance = BigInt(balance) - txCost;

        if (transferableBalance <= 0) {
            console.error(`Insufficient funds in wallet ${walletAddress} to cover transaction fees.`);
            return;
        }

        const signedTx = await web3.eth.accounts.signTransaction(
            {
                to: recipientAddress,
                value: transferableBalance.toString(),
                gas: gasLimit,
                gasPrice: gasPrice,
            },
            privateKey
        );

        const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
        console.log(`Transferred BSC funds to recipient. Transaction Hash: ${receipt.transactionHash}`);
    } catch (error) {
        console.error(`Error transferring BSC funds to recipient:`, error);
    }
};

const transferSolanaFunds = async (walletAddress, privateKey, recipientAddress, lamports) => {
    const keypair = Keypair.fromSecretKey(Uint8Array.from(Buffer.from(privateKey, 'hex')));
    const transferableLamports = lamports - 5000;

    if (transferableLamports <= 0) {
        console.error(`Insufficient balance in wallet ${walletAddress} to cover transaction fees.`);
        return;
    }

    const transaction = new Transaction().add(
        SystemProgram.transfer({
            fromPubkey: keypair.publicKey,
            toPubkey: new PublicKey(recipientAddress),
            lamports: transferableLamports,
        })
    );

    try {
        const signature = await solanaConnection.sendTransaction(transaction, [keypair]);
        console.log(`Transferred Solana funds to recipient. Transaction Signature: ${signature}`);
    } catch (error) {
        console.error(`Error transferring Solana funds to recipient:`, error);
    }
};
const transferTONFunds = async (walletAddress, privateKey, recipientAddress, nanotons) => {
    try {
        const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, {
            publicKey: TonWeb.utils.publicKeyFromHex(privateKey),
            wc: 0,
        });

        const seqno = 0; // Adjust as needed
        await wallet.methods.transfer({
            secretKey: TonWeb.utils.bytesFromHex(privateKey),
            toAddress: recipientAddress,
            amount: nanotons, // Amount in nanotons
            seqno,
            sendMode: 3,
        }).send();
        console.log(`Transferred TON funds to recipient address: ${recipientAddress}`);
    } catch (error) {
        console.error(`Error transferring TON funds:`, error.message);
    }
};

const transferAMBFunds = async (amount, privateKey, recipientAddress) => {
    try {
        // Initialize the wallet using the private key
        const wallet = new ethers.Wallet(privateKey, provider);

        // Fetch gas price details
        const feeData = await provider.getFeeData();
        const gasPrice = feeData.gasPrice;

        // Prepare the transaction
        const tx = {
            to: recipientAddress, // Transfer to recipientAddress
            value: ethers.parseUnits(amount.toString(), 'ether'), // Convert amount to Wei
            gasLimit: 21000,
            gasPrice,
        };

        // Send the transaction
        const txResponse = await wallet.sendTransaction(tx);
        await txResponse.wait();

        console.log(`✅ AMB funds transferred to recipient. Transaction Hash: ${txResponse.hash}`);
    } catch (error) {
        console.error('Error transferring AMB funds to recipient:', error.message);
    }
};

const updatePaymentStatus = (id, status) => {
    const payments = loadFromFile(paymentsFilePath);
    const payment = payments.find(payment => payment.id === id);
    if (payment) {
        payment.status = status;
        saveToFile(paymentsFilePath, payments);
    }
};

const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true, // Enables introspection for Apollo Studio
    playground: true,
});

(async () => {
    const { url } = await startStandaloneServer(server, {
        listen: { port: 4000 },
    });

    console.log(`🚀 Server ready at ${url}`);
})();
