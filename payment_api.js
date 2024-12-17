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
const paymentLinkFilePath = path.join(__dirname, 'paymentlink.json'); // File to store payment links
const custodianFilePath = path.join(__dirname, 'custodian.json'); // Path to custodian wallets file

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
const solanaConnection = new Connection('https://api.devnet.solana.com');

const AMB_RPC_URL = "https://network.ambrosus-test.io"; // Replace with your RPC URL if needed
const provider = new ethers.JsonRpcProvider(AMB_RPC_URL);

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
        getPaymentDetailsLink(id: ID!): PaymentLink
        getLinkedPayments(apiKey: String!): [StartedPayment!]!
    }
    type Mutation {
    generatePaymentAddress(
        apiKey: String!
        amount: Float!
        blockchain: String!
        recipientAddress: String!
    ): Payment
    generatePaymentLink(apiKey: String!, amount: Float!): PaymentLinkResponse
    startPaymentLink(id: ID!, blockchain: String!): PaymentDetails
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
    type PaymentLinkResponse {
        paymentLink: String!
        recipientAddresses: [RecipientAddress!]!
        amount: Float!
        status: String!
        createdAt: String!
        expiresAt: String!
    }
    type PaymentDetails {
        id: ID!
        walletAddress: String!
        privateKey: String!
        recipientAddress: String!
        amount: Float!
        convertedAmount: Float!
        status: String!
        blockchain: String!
        createdAt: String!
        expiresAt: String!
        startedAt: String!
        message: String!
        }
    type PaymentLink {
        id: ID!
        email: String!
        recipientAddresses: [RecipientAddress!]!
        amount: Float!
        status: String!
        createdAt: String!
        expiresAt: String!
        completedAt: String
    }
    type StartedPayment {
        id: ID!
        walletAddress: String!
        recipientAddress: String!
        amount: Float!
        convertedAmount: Float!
        status: String!
        blockchain: String!
        startedAt: String!
        }
    type RecipientAddress {
        blockchain: String!
        address: String!
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
        getPaymentDetailsLink: async (_, { id }) => {
            try {
                // Load payment links dynamically
                const paymentLinks = loadFromFile(paymentLinkFilePath);

                // Find the payment link by ID
                const payment = paymentLinks.find((link) => link.id === id);

                if (!payment) {
                    console.error(`No payment found with the ID: ${id}`);
                    throw new Error(`No payment found with the ID: ${id}`);
                }

                return payment; // Return the payment details
            } catch (error) {
                console.error(`Error fetching payment details for ID: ${id}`, error);
                throw new Error('An error occurred while fetching payment details.');
            }
        },
        getLinkedPayments: async (_, { apiKey }) => {
            try {
                // Load API keys dynamically
                const apiKeys = loadFromFile(path.join(__dirname, 'apikeys.json'));
        
                // Validate the provided API key and fetch user email
                const apiKeyEntry = apiKeys.find((key) => key.apiKey === apiKey);
                if (!apiKeyEntry) {
                    console.error(`Invalid or unauthorized API Key: ${apiKey}`);
                    throw new Error('Invalid or unauthorized API Key');
                }
        
                const userEmail = apiKeyEntry.userData?.email; // Extract email from user data
                if (!userEmail) {
                    console.error(`No email found for API Key: ${apiKey}`);
                    throw new Error('No email found for the provided API Key');
                }
        
                // Load linked payments dynamically
                const linkedPayments = loadFromFile(path.join(__dirname, 'linkpay.json'));
        
                // Filter payments by user email
                const userPayments = linkedPayments.filter((payment) => payment.email === userEmail);
        
                if (userPayments.length === 0) {
                    console.log(`No linked payments found for user: ${userEmail}`);
                    return [];
                }
        
                console.log(`Fetched linked payments for user: ${userEmail}`);
                return userPayments;
            } catch (error) {
                console.error('Error fetching linked payments:', error);
                throw new Error('An error occurred while fetching linked payments.');
            }
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
        generatePaymentLink: async (_, { apiKey, amount }) => {
            // Load data dynamically
            const apiKeys = loadFromFile(apikeysFilePath);
            const custodianWallets = loadFromFile(custodianFilePath);

            // Validate the API key
            const apiKeyEntry = apiKeys.find((key) => key.apiKey === apiKey);
            if (!apiKeyEntry) {
                throw new Error('Invalid or unauthorized API Key');
            }

            const userEmail = apiKeyEntry.userData.email.trim().toLowerCase(); // Normalize email

            // Find the custodian wallet linked to the user's email
            const userCustodian = custodianWallets.find(
                (entry) => entry.email.trim().toLowerCase() === userEmail
            );

            if (!userCustodian) {
                console.error(`No custodian wallet found for email: ${userEmail}`);
                throw new Error(`No custodian wallet found for email: ${userEmail}`);
            }

            // Validate the input amount
            if (amount <= 0) {
                throw new Error('Amount must be greater than 0');
            }

            // Map custodian wallets into recipient addresses
            const recipientAddresses = [
                { blockchain: 'BSC', address: userCustodian.bsc },
                { blockchain: 'Solana', address: userCustodian.solana },
                { blockchain: 'TON', address: userCustodian.ton },
                { blockchain: 'AMB', address: userCustodian.amb },
            ].filter((wallet) => wallet.address); // Filter out empty addresses

            if (recipientAddresses.length === 0) {
                throw new Error(`No valid recipient addresses found for email: ${userEmail}`);
            }

            // Create a unique payment ID
            const paymentId = createPaymentId();

            // Generate the current timestamp and expiration timestamp
            const createdAt = new Date().toISOString();
            const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 minutes from now

            // Create a new payment link record
            const newPaymentLink = {
                id: paymentId,
                email: userEmail,
                recipientAddresses,
                amount,
                status: 'Pending',
                createdAt,
                expiresAt,
            };

            // Save the payment link in paymentlink.json
            const paymentLinks = loadFromFile(paymentLinkFilePath);
            paymentLinks.push(newPaymentLink);
            saveToFile(paymentLinkFilePath, paymentLinks);

            // Return the generated payment link
            return {
                paymentLink: `https://payment-platform.com/pay/${paymentId}`,
                recipientAddresses,
                amount,
                status: newPaymentLink.status,
                createdAt: newPaymentLink.createdAt,
                expiresAt: newPaymentLink.expiresAt,
            };
        },
        startPaymentLink: async (_, { id, blockchain }) => {
            try {
                console.log(`Starting payment for ID: ${id} on blockchain: ${blockchain}`);
        
                // Load payment links dynamically
                const paymentLinks = loadFromFile(paymentLinkFilePath);
                const startedPayments = loadFromFile(path.join(__dirname, 'linkpay.json'));
        
                // Find the payment link by ID
                const payment = paymentLinks.find((link) => link.id === id);
        
                if (!payment) {
                    console.error(`No payment found with the ID: ${id}`);
                    throw new Error(`No payment found with the ID: ${id}`);
                }
        
                // Ensure the link is still valid
                const currentTime = new Date();
                if (new Date(payment.expiresAt) < currentTime) {
                    console.error(`Payment link expired for ID: ${id}`);
                    throw new Error('This payment link has expired.');
                }
        
                // Ensure the payment is not already started
                if (payment.status === 'Started') {
                    console.warn(`Payment already started for ID: ${id}`);
                    return {
                        message: `Payment for this link has already started.`,
                        paymentLink: `https://payment-platform.com/pay/${id}`,
                        status: 'Started',
                    };
                }
        
                // Find the recipient address based on the chosen blockchain
                const recipientAddressEntry = payment.recipientAddresses?.find(
                    (entry) => entry.blockchain === blockchain
                );
        
                if (!recipientAddressEntry) {
                    console.error(`No recipient address found for blockchain: ${blockchain} and ID: ${id}`);
                    throw new Error(`No recipient address found for blockchain: ${blockchain}`);
                }
        
                const recipientAddress = recipientAddressEntry.address;
        
                // Generate wallet address depending on the blockchain
                let walletAddress, privateKey, convertedAmount;
                try {
                    if (blockchain === 'AMB') {
                        const wallet = ethers.Wallet.createRandom();
                        walletAddress = wallet.address;
                        privateKey = wallet.privateKey;
                    } else if (blockchain === 'BSC') {
                        const account = web3.eth.accounts.create();
                        walletAddress = account.address;
                        privateKey = account.privateKey;
                    } else if (blockchain === 'Solana') {
                        const keypair = Keypair.generate();
                        walletAddress = keypair.publicKey.toBase58();
                        privateKey = Buffer.from(keypair.secretKey).toString('hex');
                    } else if (blockchain === 'TON') {
                        const keyPair = TonWeb.utils.newKeyPair();
                        const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, { publicKey: keyPair.publicKey, wc: 0 });
                        walletAddress = (await wallet.getAddress()).toString(true, true, false); // UQ format
                        privateKey = TonWeb.utils.bytesToHex(keyPair.secretKey);
                    } else {
                        throw new Error('Unsupported blockchain');
                    }
        
                    const livePrice = await fetchLivePrice(blockchain);
                    if (!livePrice || livePrice <= 0) {
                        throw new Error('Failed to fetch live price');
                    }
        
                    convertedAmount = payment.amount / livePrice;
                } catch (genError) {
                    console.error(`Error generating wallet for blockchain ${blockchain}:`, genError.message);
                    throw new Error('Failed to generate wallet or fetch live price.');
                }
        
                // Update the payment status to 'Started'
                payment.status = 'Started';
                const updatedPayment = {
                    ...payment,
                    walletAddress,
                    privateKey,
                    recipientAddress,
                    convertedAmount,
                    startedAt: new Date().toISOString(),
                };
        
                // Save the updated payment link
                saveToFile(paymentLinkFilePath, paymentLinks);
        
                // Save to linkpay.json
                startedPayments.push(updatedPayment);
                saveToFile(path.join(__dirname, 'linkpay.json'), startedPayments);
        
                console.log(`Payment successfully started for ID: ${id}`);
        
                // Monitor the payment for completion
                monitorPayment(updatedPayment, id);
        
                return {
                    id: payment.id,
                    walletAddress,
                    recipientAddress,
                    amount: payment.amount,
                    convertedAmount,
                    status: payment.status,
                    blockchain,
                    createdAt: payment.createdAt,
                    expiresAt: payment.expiresAt,
                    startedAt: updatedPayment.startedAt,
                };
            } catch (error) {
                console.error(`Error starting payment link for ID: ${id}:`, error.message);
                throw new Error('An error occurred while starting the payment.');
            }
        },        
    },
};
 
const monitorPayment = async (payment, id) => {
    const { walletAddress, privateKey, recipientAddress, blockchain, convertedAmount } = payment;
    const endTime = Date.now() + 10 * 60 * 1000; // 10 minutes from now

    const interval = setInterval(async () => {
        try {
            if (Date.now() >= endTime) {
                clearInterval(interval);
                updatePaymentStatus(id, 'Expired');
                console.error(`Payment monitoring expired for ID: ${id}, wallet: ${walletAddress}`);

                // Update the payment link status to 'Expired'
                updatePaymentLinkStatus(id, 'Expired');
                return;
            }

            if (blockchain === 'BSC') {
                const balance = await web3.eth.getBalance(walletAddress);
                if (parseFloat(web3.utils.fromWei(balance, 'ether')) >= convertedAmount) {
                    clearInterval(interval);
                    await transferBSCFunds(walletAddress, privateKey, recipientAddress, balance);
                    updatePaymentStatus(id, 'Completed');
                    updatePaymentLinkStatus(id, 'Completed');
                    console.log(`Payment completed for ID: ${id}, wallet: ${walletAddress}`);
                }
            } else if (blockchain === 'Solana') {
                const publicKey = new PublicKey(walletAddress);
                const balance = await solanaConnection.getBalance(publicKey);
                if (balance >= convertedAmount * 1e9) { // Converted amount to lamports
                    clearInterval(interval);
                    await transferSolanaFunds(walletAddress, privateKey, recipientAddress, balance);
                    updatePaymentStatus(id, 'Completed');
                    updatePaymentLinkStatus(id, 'Completed');
                    console.log(`Payment completed for ID: ${id}, wallet: ${walletAddress}`);
                }
            } else if (blockchain === 'TON') {
                const balance = await tonweb.provider.getBalance(walletAddress);
                if (balance >= convertedAmount * 1e9) { // Convert TON to nanograms
                    clearInterval(interval);
                    await transferTONFunds(walletAddress, privateKey, recipientAddress, balance);
                    updatePaymentStatus(id, 'Completed');
                    updatePaymentLinkStatus(id, 'Completed');
                    console.log(`Payment completed for ID: ${id}, wallet: ${walletAddress}`);
                }
            } else if (blockchain === 'AMB') {
                const balance = await provider.getBalance(walletAddress);
                if (parseFloat(ethers.formatEther(balance)) >= convertedAmount) {
                    clearInterval(interval);
                    await transferAmbFunds(walletAddress, privateKey, recipientAddress, balance);
                    updatePaymentStatus(id, 'Completed');
                    updatePaymentLinkStatus(id, 'Completed');
                    console.log(`Payment completed for ID: ${id}, wallet: ${walletAddress}`);
                }
            }
        } catch (error) {
            console.error(`Error monitoring payment for ID: ${id}, wallet: ${walletAddress}`, error);
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
        const keyPair = TonWeb.utils.keyPairFromSecretKey(TonWeb.utils.hexToBytes(privateKey)); // Generate key pair

        const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, {
            publicKey: keyPair.publicKey,
            wc: 0, // Workchain ID (0 is the standard workchain)
        });

        // Set seqno explicitly to 0 for testing or for new wallets
        const seqno = 0;

        await wallet.methods
            .transfer({
                secretKey: keyPair.secretKey,
                toAddress: recipientAddress,
                amount: nanotons, // Amount in nanotons
                seqno: seqno,
                sendMode: 3,
            })
            .send();

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

const updatePaymentLinkStatus = (id, status) => {
    const paymentLinks = loadFromFile(paymentLinkFilePath);
    const paymentLink = paymentLinks.find((link) => link.id === id);

    if (paymentLink) {
        paymentLink.status = status;
        if (status === 'Completed') {
            paymentLink.completedAt = new Date().toISOString(); // Add completion timestamp
        }
        saveToFile(paymentLinkFilePath, paymentLinks);
        console.log(`Payment link status updated to '${status}' for ID: ${id}`);
    } else {
        console.error(`No payment link found for ID: ${id} to update status.`);
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
