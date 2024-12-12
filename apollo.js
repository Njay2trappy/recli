const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const Web3 = require('web3');
const { Keypair, Connection, clusterApiUrl, SystemProgram, Transaction, PublicKey } = require('@solana/web3.js');
const axios = require('axios');
const jwt = require('jsonwebtoken');

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
        login(email: String!, password: String!): AuthPayload!
        adminLogin(email: String!, password: String!): AdminAuthPayload!
        getAllUsers(adminToken: String!): [User!]!
        getDeletedUsers(adminToken: String!): [User!]!
        getDeposits(userId: ID!): [Deposit!]!
        getWalletAddresses(userId: ID!, blockchain: String!): WalletAddresses!
        getUsers: [User!]!
        getUserById(userId: ID!): User!
    }

    type Mutation {
        generatePaymentAddress(userId: String!, amount: Float!, blockchain: String!): Payment
        createUser(
      firstName: String!,
      lastName: String!,
      email: String!,
      password: String!,
      gender: String,
      username: String!
    ): User!
    createAdmin(
      firstName: String!,
      lastName: String!,
      email: String!,
      password: String!,
      username: String!
    ): Admin!
    deleteUser(adminToken: String!, userId: ID!): String!
    createDeposit(userId: ID!, amount: Float!): Deposit!
    createCustodian(username: String!, token: String!): Custodian!
    }
    type User {
    id: ID!
    firstName: String!
    lastName: String!
    email: String!
    password: String!
    gender: String
    username: String!
    createdAt: String!
    updatedAt: String!
  }
  type Admin {
    id: ID!
    firstName: String!
    lastName: String!
    email: String!
    username: String!
    createdAt: String!
  }

  type AuthPayload {
    token: String!
    user: User!
  }
  type AdminAuthPayload {
    adminToken: String!
    admin: Admin!
  }
  type Deposit {
    id: ID!
    userId: ID!
    amount: Float!
    createdAt: String!
  }

  type WalletAddresses {
    bsc: String
    solana: String
  }

  type Custodian {
    userId: ID!
    username: String!
    bsc: String!
    solana: String!
  }
`;

// Mock database
const users = [];
const admins = []
const deposits = [];
const custodians = [];
const saveAdminsToFile = () => {
    fs.writeFileSync('admins.json', JSON.stringify(admins, null, 2));
  };
  
  const loadAdminsFromFile = () => {
    if (fs.existsSync('admins.json')) {
      return JSON.parse(fs.readFileSync('admins.json'));
    }
    return [];
  };
  
  // Load admins on start
  Object.assign(admins, loadAdminsFromFile());
const deletedUsers = [];
const saveUsersToFile = () => {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
};
const loadUsersFromFile = () => {
  if (fs.existsSync('users.json')) {
    return JSON.parse(fs.readFileSync('users.json'));
  }
  return [];
};
const loadDeletedUsersFromFile = () => {
    if (fs.existsSync('spam.json')) {
      return JSON.parse(fs.readFileSync('spam.json'));
    }
    return [];
  };
  const saveDepositsToFile = () => {
    fs.writeFileSync('deposits.json', JSON.stringify(deposits, null, 2));
  };
  const saveCustodiansToFile = () => {
    fs.writeFileSync('custodian.json', JSON.stringify(custodians, null, 2));
  };
  const loadDepositsFromFile = () => {
    if (fs.existsSync('deposits.json')) {
      return JSON.parse(fs.readFileSync('deposits.json'));
    }
    return [];
  };
  const loadCustodiansFromFile = () => {
    if (fs.existsSync('custodian.json')) {
      return JSON.parse(fs.readFileSync('custodian.json'));
    }
    return [];
  };

// Load users on start
Object.assign(users, loadUsersFromFile());
Object.assign(deletedUsers, loadDeletedUsersFromFile());
Object.assign(deposits, loadDepositsFromFile());
Object.assign(custodians, loadCustodiansFromFile());
const ADMIN_SECRET = 'adminsecretkey';

// Secret for JWT
const JWT_SECRET = 'supersecretkey';

const generateBscWalletAddress = () => {
    const web3 = new Web3();
    const account = web3.eth.accounts.create();
    return account.address;
  };
  
  const generateSolanaWalletAddress = () => {
    const keypair = Keypair.generate();
    return keypair.publicKey.toBase58();
  };
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
        login: (_, { email, password }) => {
            const user = users.find((user) => user.email === email);
            if (!user) {
              throw new Error('User not found');
            }
      
            if (user.password !== password) {
              throw new Error('Invalid password');
            }
      
            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
              expiresIn: '1h',
            });
      
            return { token, user: { ...user, password: null } }; // Omit password from response
          },
          adminLogin: (_, { email, password }) => {
            const admin = admins.find((admin) => admin.email === email);
            if (!admin) {
              throw new Error('Admin not found');
            }
      
            if (admin.password !== password) {
              throw new Error('Invalid password');
            }
      
            const adminToken = jwt.sign({ id: admin.id, email: admin.email }, ADMIN_SECRET, {
              expiresIn: '10m',
            });
      
            return { adminToken, admin };
          },
          getAllUsers: (_, { adminToken }) => {
            const admin = jwt.verify(adminToken, ADMIN_SECRET);
            if (!admin) {
              throw new Error('Invalid admin token');
            }
            return users.map((user) => ({ ...user, password: null }));
          },
          getDeletedUsers: (_, { adminToken }) => {
            const admin = jwt.verify(adminToken, ADMIN_SECRET);
            if (!admin) {
              throw new Error('Invalid admin token');
            }
            return deletedUsers;
          },
          getDeposits: (_, { userId }) => {
            return deposits.filter((deposit) => deposit.userId === userId);
          },
          getWalletAddresses: (_, { userId, blockchain }) => {
            const custodian = custodians.find((entry) => entry.userId === userId);
      
            if (!custodian) {
              throw new Error('User wallet not found');
            }
      
            if (blockchain === 'BSC') {
              return { bsc: custodian.bsc, solana: null };
            } else if (blockchain === 'Solana') {
              return { bsc: null, solana: custodian.solana };
            } else {
              throw new Error('Unsupported blockchain');
            }
          },
          getUsers: () => {
            const users = loadUsersFromFile();
            return users;
          },
          getUserById: (_, { userId }) => {
            const users = loadUsersFromFile();
            const user = users.find((user) => user.id === userId);
            if (!user) {
              throw new Error('User not found');
            }
            return user;
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
        createUser: (_, { firstName, lastName, email, password, gender, username }) => {
            if (users.find((user) => user.email === email)) {
              throw new Error('User already exists');
            }
      
            const newUser = {
              id: (users.length + 1).toString(), // Ensure id is a string
              firstName,
              lastName,
              email,
              password,
              gender,
              username,
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            };
      
            users.push(newUser);
            saveUsersToFile();
            return { ...newUser, password: null }; // Return user without password
          },
          createAdmin: async (_, { firstName, lastName, email, password, username }) => {
            if (admins.find((admin) => admin.email === email)) {
              throw new Error('Admin already exists');
            }
          
            const newAdmin = {
              id: (admins.length + 1).toString(),
              firstName,
              lastName,
              email,
              username,
              password, // Store as plaintext or hashed for security
              createdAt: new Date().toISOString(),
            };
          
            admins.push(newAdmin);
            saveAdminsToFile(); // Save admin details to the file
          
            return newAdmin;
          },      
        deleteUser: (_, { adminToken, userId }) => {
            const admin = jwt.verify(adminToken, ADMIN_SECRET);
            if (!admin) {
              throw new Error('Invalid admin token');
            }
          
            const usersFromFile = loadUsersFromFile(); // Dynamically load the users from the file
            const userIndex = usersFromFile.findIndex((user) => user.id === userId);
          
            if (userIndex === -1) {
              throw new Error('User not found');
            }
          
            const [removedUser] = usersFromFile.splice(userIndex, 1); // Remove the user
            deletedUsers.push(removedUser);
          
            // Save updated users and deleted users to their respective files
            fs.writeFileSync('users.json', JSON.stringify(usersFromFile, null, 2));
            saveDeletedUsersToFile();
          
            return `User with ID ${userId} has been deleted.`;
          },    
          createDeposit: (_, { userId, amount }) => {
            if (amount <= 0) {
              throw new Error('Deposit amount must be greater than zero');
            }
      
            const newDeposit = {
              id: (deposits.length + 1).toString(), // Ensure id is a string
              userId,
              amount,
              createdAt: new Date().toISOString(),
            };
      
            deposits.push(newDeposit);
            saveDepositsToFile(); // Save to deposits.json file
            return newDeposit;
          },
          createCustodian: (_, { username, token }) => {
            if (custodians.find((entry) => entry.username === username)) {
              throw new Error('Custodian already exists for this user');
            }
      
            const userId = crypto.randomUUID(); // Generate a unique user ID
            const bscAddress = generateBscWalletAddress();
            const solanaAddress = generateSolanaWalletAddress();
      
            const newCustodian = {
              userId,
              username,
              bsc: bscAddress,
              solana: solanaAddress,
            };
      
            custodians.push(newCustodian);
            saveCustodiansToFile(); // Save to custodian.json file
      
            return newCustodian;
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
            apiKey: ''  // Add Apollo Studio API key here
        }),
    });

    console.log(`🚀 Server ready at ${url}`);
})();