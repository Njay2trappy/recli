const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const Web3 = require('web3');
const { Keypair, Connection, clusterApiUrl, SystemProgram, Transaction, PublicKey } = require('@solana/web3.js');
const axios = require('axios');

// File paths for JSON storage
const paymentsFilePath = path.join(__dirname, 'payments.json');

// Admin Wallets
const BSC_ADMIN_WALLET = "0x15Dc6AB3B9b45821d6c918Ec1b256F6f7470E4DC";
const SOLANA_ADMIN_WALLET = "B6ze7uHAdKeXucs3uguYKbcGeeiz3pzizdLbz3rPembe";
const BSC_TESTNET_RPC = "https://data-seed-prebsc-1-s1.binance.org:8545";

// Initialize Web3 for BSC
const web3 = new Web3(BSC_TESTNET_RPC);

// Initialize Solana Connection
const solanaConnection = new Connection(clusterApiUrl('devnet'));

// Utility functions to handle payments JSON file
const readPayments = () => {
    if (!fs.existsSync(paymentsFilePath)) {
        fs.writeFileSync(paymentsFilePath, JSON.stringify([])); // Create file if it doesn't exist
    }
    const data = fs.readFileSync(paymentsFilePath, 'utf8');
    return JSON.parse(data);
};

const writePayments = (payments) => {
    fs.writeFileSync(paymentsFilePath, JSON.stringify(payments, null, 2)); // Pretty print JSON
};

// Fetch live price for BNB or SOL in USD
const fetchLivePrice = async (blockchain) => {
    try {
        if (blockchain === 'BSC') {
            const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=binancecoin&vs_currencies=usd');
            return response.data.binancecoin.usd;
        } else if (blockchain === 'Solana') {
            const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
            return response.data.solana.usd;
        }
        throw new Error('Unsupported blockchain');
    } catch (error) {
        console.error('Error fetching live price:', error);
        throw new Error('Failed to fetch live price');
    }
};

// GraphQL Schema
const typeDefs = gql`
    type Payment {
        id: ID!
        userId: String!
        walletAddress: String!
        privateKey: String!
        amount: Float!
        status: String!
        createdAt: String!
        blockchain: String!
        convertedAmount: Float!
    }

    type Query {
        getPayment(id: ID!): Payment
        getPaymentsByUser(userId: String!): [Payment]
    }

    type Mutation {
        generatePaymentAddress(userId: String!, amount: Float!, blockchain: String!): Payment
    }
`;

// GraphQL Resolvers
const resolvers = {
    Query: {
        getPayment: (_, { id }) => {
            const payments = readPayments();
            return payments.find(payment => payment.id === id) || null;
        },
        getPaymentsByUser: (_, { userId }) => {
            const payments = readPayments();
            return payments.filter(payment => payment.userId === userId);
        },
    },
    Mutation: {
        generatePaymentAddress: async (_, { userId, amount, blockchain }) => {
            const payments = readPayments();
            let walletAddress, privateKey;

            // Generate wallet address
            if (blockchain === 'BSC') {
                const account = web3.eth.accounts.create();
                walletAddress = account.address;
                privateKey = account.privateKey;
            } else if (blockchain === 'Solana') {
                const keypair = Keypair.generate();
                walletAddress = keypair.publicKey.toBase58();
                privateKey = Buffer.from(keypair.secretKey).toString('hex');
            } else {
                throw new Error('Unsupported blockchain');
            }

            // Fetch live conversion rate and calculate converted amount
            const livePrice = await fetchLivePrice(blockchain);
            const convertedAmount = amount / livePrice;

            const newPayment = {
                id: uuidv4(),
                userId,
                walletAddress,
                privateKey,
                amount,
                convertedAmount,
                status: 'Pending',
                createdAt: new Date().toISOString(),
                blockchain,
            };

            payments.push(newPayment);
            writePayments(payments);

            monitorPayment(newPayment);

            return newPayment;
        },
    },
};

const monitorPayment = async (payment) => {
    const { walletAddress, privateKey, blockchain, convertedAmount } = payment;
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
                    await transferBSCFunds(walletAddress, privateKey, balance);
                    updatePaymentStatus(payment.id, 'Completed');
                    console.log(`Payment completed for BSC wallet ${walletAddress}`);
                }
            } else if (blockchain === 'Solana') {
                const publicKey = new PublicKey(walletAddress);
                const balance = await solanaConnection.getBalance(publicKey);
                if (balance >= convertedAmount * 1e9) { // Converted amount to lamports
                    clearInterval(interval);
                    await transferSolanaFunds(walletAddress, privateKey, balance);
                    updatePaymentStatus(payment.id, 'Completed');
                    console.log(`Payment completed for Solana wallet ${walletAddress}`);
                }
            }
        } catch (error) {
            console.error(`Error monitoring payment for wallet ${walletAddress}:`, error);
        }
    }, 2000); // Check every 2 seconds
};


const transferBSCFunds = async (walletAddress, privateKey, balance) => {
    try {
        // Get current gas price
        const gasPrice = await web3.eth.getGasPrice();
        const gasLimit = 21000; // Gas limit for a simple transfer

        // Calculate total transaction cost
        const txCost = BigInt(gasPrice) * BigInt(gasLimit);

        // Ensure there is enough balance to cover the transaction
        const transferableBalance = BigInt(balance) - txCost;

        if (transferableBalance <= 0) {
            console.error(`Insufficient funds in wallet ${walletAddress} to cover transaction fees.`);
            return;
        }

        // Prepare transaction
        const signedTx = await web3.eth.accounts.signTransaction(
            {
                to: BSC_ADMIN_WALLET,
                value: transferableBalance.toString(),
                gas: gasLimit,
                gasPrice: gasPrice,
            },
            privateKey
        );

        // Send transaction
        const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
        console.log(`Transferred BSC funds from ${walletAddress} to admin. Transaction Hash: ${receipt.transactionHash}`);
    } catch (error) {
        console.error(`Error transferring BSC funds from ${walletAddress}:`, error);
    }
};


const transferSolanaFunds = async (walletAddress, privateKey, lamports) => {
    const keypair = Keypair.fromSecretKey(Uint8Array.from(Buffer.from(privateKey, 'hex')));

    // Deduct 5000 lamports for transaction fees (adjust as needed)
    const transferableLamports = lamports - 5000;
    if (transferableLamports <= 0) {
        console.error(`Insufficient balance in wallet ${walletAddress} to cover transaction fees.`);
        return;
    }

    const transaction = new Transaction().add(
        SystemProgram.transfer({
            fromPubkey: keypair.publicKey,
            toPubkey: new PublicKey(SOLANA_ADMIN_WALLET),
            lamports: transferableLamports,
        })
    );

    try {
        const signature = await solanaConnection.sendTransaction(transaction, [keypair]);
        console.log(`Transferred Solana funds from ${walletAddress} to admin. Transaction Signature: ${signature}`);
    } catch (error) {
        console.error(`Error transferring Solana funds from ${walletAddress}:`, error);
    }
};

const updatePaymentStatus = (id, status) => {
    const payments = readPayments();
    const payment = payments.find(payment => payment.id === id);
    if (payment) {
        payment.status = status;
        writePayments(payments);
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
        context: async () => ({
            apiKey: process.env.APOLLO_KEY, // Add Apollo Studio API key here
        }),
    });

    console.log(`🚀 Server ready at ${url}`);
})();