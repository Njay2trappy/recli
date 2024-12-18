const { ApolloClient, InMemoryCache } = require('@apollo/client/core');
const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const axios = require('axios');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');
const Web3 = require('web3');
const { Keypair, Connection, clusterApiUrl, SystemProgram, Transaction, PublicKey } = require('@solana/web3.js');
const TonWeb = require('tonweb');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');

// File paths for JSON storage
const paymentsFilePath = path.join(__dirname, 'payments.json');
const paymentLinkFilePath = path.join(__dirname, 'paymentlink.json'); // File to store payment links
const custodianFilePath = path.join(__dirname, 'custodian.json'); // Path to custodian wallets file
const apikeysFilePath = path.join(__dirname, 'apikeys.json'); // Path to API keys file

// Utility functions to read/write files
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

const client = new ApolloClient({
  uri: 'https://recli.onrender.com/graphql', // Your GraphQL endpoint
  cache: new InMemoryCache(),
  headers: {
    'x-apollo-key': 'service:My-Graph-xlm7p:4e6pmeQtltz18VK0Dn42Vw', // Apollo Key
  },
});

const JWT_SECRET = 'supersecretkey';
const ADMIN_SECRET = 'adminsecretkey';

const validateUserToken = (token) => {
    try {
      console.log('Validating user token:', token);
  
      // Reload tokens from the file to ensure it's up to date
      const userTokens = loadFromFile('tokens.json');  
      // Trim token to remove unnecessary whitespace
      token = token.trim();
  
      // Check if the token exists in tokens.json
      if (!userTokens.includes(token)) {
        console.error('Token not found in tokens.json:', token);
        throw new Error('Unauthorized: Invalid user token');
      }
  
      // Decode and verify the token
      const decoded = jwt.verify(token, JWT_SECRET); // Ensure JWT_SECRET matches the signing key  
      return decoded; // Return the decoded payload
    } catch (err) {
      throw new Error('Unauthorized: Invalid or expired user token');
    }
};

const generateId = (prefix = 'Order') => {
    // Generate a random string and encode it in base64
    const randomString = crypto.randomBytes(16).toString('hex');
    const base64String = Buffer.from(randomString).toString('base64');
    
    // Combine the base64 string and prefix
    return `${base64String}`;
};

const validateAdminToken = (adminToken) => {
    try {
      console.log('Validating admin token:', adminToken);
  
      // Reload admin tokens from adtokens.json
      const adminTokens = loadFromFile('adtokens.json');  
      // Trim the token to avoid formatting issues
      adminToken = adminToken.trim();
  
      // Check if the token exists in adtokens.json
      if (!adminTokens.includes(adminToken)) {
        console.error('Admin token not found in adtokens.json:', adminToken);
        throw new Error('Unauthorized: Invalid admin token');
      }
  
      // Decode and verify the admin token
      const decoded = jwt.verify(adminToken, ADMIN_SECRET); // Ensure ADMIN_SECRET matches the signing key  
      return decoded; // Return the decoded payload
    } catch (err) {
      console.error('Admin token validation error:', err.message);
      throw new Error('Unauthorized: Invalid or expired admin token');
    }
};


// Helper functions to generate wallet addresses
const generateBscWalletAddress = () => {
    const web3 = new Web3('https://bsc-dataseed.binance.org/');
    const account = web3.eth.accounts.create();
    return account.address;
};
  
const generateSolanaWalletAddress = () => {
    const keypair = Keypair.generate();
    return keypair.publicKey.toBase58();
};
  
const generateTonWalletAddress = async () => {
    const tonweb = new TonWeb(new TonWeb.HttpProvider('https://testnet.toncenter.com/api/v2/jsonRPC', {
      apiKey: '8723f42a9a980ba38692832aad3d42fcbe0f0435600c6cd03d403e800bdd2e88'
    }));
  
    const keyPair = TonWeb.utils.newKeyPair();
    const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, { publicKey: keyPair.publicKey, wc: 0 });
    const walletAddress = (await wallet.getAddress()).toString(true, true, false);
    return walletAddress;
};
  
const generateAmbWalletAddress = () => {
    const wallet = ethers.Wallet.createRandom();
    return wallet.address;
};
  

// Define the GraphQL schema
const typeDefs = gql`
    type Query {
        login(email: String!, password: String!): AuthPayload!
        adminLogin(email: String!, password: String!): AdminAuthPayload!
        getAllUsers(adminToken: String): [User!]!
        getDeletedUsers(adminToken: String): [User!]!
        getTokens(adminToken: String!): [String!]!
        getWalletAddresses(token: String!): CustodianOrMessage!
        getCustodians(adminToken: String!): UsersOrMessage!
        queryAPIKey(token: String!): APIKey!
        getPayment(adminToken: String!): [Payment]
        getPaymentsByUser(userToken: String, apiKey: String): [Payment]
        getPaymentDetailsLink(id: ID!): PaymentLink
        getLinkedPayments(apiKey: String!): [StartedPayment!]!
        generateOTP(email: String!): OTPResponse!
        getUsers(token: String!): User!
    }
    type TokenPayload {
        token: String!
    }
    type Mutation {
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
        deleteUser(adminToken: String, userId: ID!): String!
        logout(token: String!): String!
        createCustodian(token: String!): CustodianOrMessage!
        adminSignOut(adminToken: String!): Message!
        generateAPIKey(token: String!): APIKey!
        revokeAPIKey(token: String!): APIKey!
        createSuperKey(adminToken: String!): APIKey!
        generatePaymentAddress(
            apiKey: String!
            amount: Float!
            blockchain: String!
            recipientAddress: String!
        ): Payment
        generatePaymentLink(apiKey: String!, amount: Float!): PaymentLinkResponse
        startPaymentLink(id: ID!, blockchain: String!): PaymentDetails
        changeUserPassword(token: String, otp: String, oldPassword: String, newPassword: String!): String!
        changeAdminPassword(adminToken: String, otp: String, oldPassword: String, newPassword: String!): String!
        changeUserEmail(token: String, otp: String, newEmail: String!): String!
    }
    type APIKey {
        key: String!
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
    type Message {
            message: String!
        }
        type CustodianOrMessage {
        message: String
        userId: ID
        email: String
        bsc: String
        solana: String
        ton: String
        amb: String
    }
    type UsersOrMessage {
        message: String
        users: [User!]
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
    type OTPResponse {
    otp: String!
    expiry: String!
    }
`;

let otpStore = {}; // Temporary store for OTPs

// Generate OTP function
const generateOTP = (email, isAdmin) => {
  const otp = (Math.floor(100000 + Math.random() * 900000)).toString(); // 6-digit OTP
  const expiry = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // Expires in 15 minutes

  const admins = loadFromFile('admins.json');
  const users = loadFromFile('users.json');

  if (isAdmin) {
    const admin = admins.find((a) => a.email === email);
    if (!admin) {
      throw new Error('Admin email not found');
    }
    otpStore[otp] = { expiry, id: admin.id, type: 'admin' };
  } else {
    const user = users.find((u) => u.email === email);
    if (!user) {
      throw new Error('User email not found');
    }
    otpStore[otp] = { expiry, id: user.id, type: 'user' };
  }

  setTimeout(() => delete otpStore[otp], 15 * 60 * 1000); // Automatically remove expired OTP
  return { otp, expiry };
};

// BSC testnet Configuration
const BSC_TESTNET_RPC = "https://data-seed-prebsc-1-s1.binance.org:8545";
const web3 = new Web3(BSC_TESTNET_RPC);

// TON testnet configuration
const tonweb = new TonWeb(new TonWeb.HttpProvider('https://testnet.toncenter.com/api/v2/jsonRPC', {
    apiKey: '8723f42a9a980ba38692832aad3d42fcbe0f0435600c6cd03d403e800bdd2e88',
}));

// Initialize Solana Connection
const solanaConnection = new Connection('https://api.devnet.solana.com');

//AMB connection
const AMB_RPC_URL = "https://network.ambrosus-test.io"; // Replace with your RPC URL if needed
const provider = new ethers.JsonRpcProvider(AMB_RPC_URL);


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
            const tonUQRegex = /^[0Q][A-Za-z0-9_-]{47}$/; // Example regex for UQ address format
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


const createPaymentId = () => {
    const uuid = uuidv4().replace(/-/g, ''); // Remove dashes from UUID
    const suffix = "Order"; // Static or dynamic suffix
    const id = Buffer.from(`${uuid}:${suffix}`).toString('base64'); // Encode in Base64
    return id;
};

// Resolver functions
const resolvers = {
    Query: {
        login: (_, { email, password }) => {
            const users = loadFromFile('users.json'); // Load users dynamically
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
          
            const userTokens = loadFromFile('tokens.json'); // Always load the latest tokens
            userTokens.push(token);
            saveToFile('tokens.json', userTokens); // Save updated tokens
          
            return { token, user: { ...user, password: null } };
          },       
          adminLogin: (_, { email, password }) => {
            const admins = loadFromFile('admins.json'); // Load admins dynamically
            const admin = admins.find((admin) => admin.email === email);
          
            if (!admin) {
              throw new Error('Admin not found');
            }
          
            if (admin.password !== password) {
              throw new Error('Invalid password');
            }
          
            const adminToken = jwt.sign(
              { id: admin.id, email: admin.email, admin: true },
              ADMIN_SECRET,
              { expiresIn: '1h' }
            );
          
            const adminTokens = loadFromFile('adtokens.json'); // Always load the latest tokens
            adminTokens.push(adminToken);
            saveToFile('adtokens.json', adminTokens); // Save updated admin tokens
          
            // Ensure the resolver returns both the adminToken and the admin object
            return {
              adminToken,
              admin, // Return the valid admin object
            };
        },    
        getAllUsers: (_, { adminToken }) => {
            validateAdminToken(adminToken); // Dynamically validate admin token
            const users = loadFromFile('users.json'); // Load users dynamically
            return users.map((user) => ({ ...user, password: null })); // Return users without passwords
        },    
        getDeletedUsers: (_, { adminToken }) => {
            validateAdminToken(adminToken); // Validate admin token
            return loadFromFile('spam.json'); // Load deleted users dynamically
        },
        getTokens: (_, { adminToken }) => {
            validateAdminToken(adminToken); // Validate admin token
            return loadFromFile('tokens.json'); // Return all user tokens
        },
        getWalletAddresses: (_, { token }) => {
            // Reload tokens.json to get the latest tokens
            const userTokens = loadFromFile('tokens.json');      
            // Validate the user token
            token = token.trim(); // Trim any whitespace
            if (!userTokens.includes(token)) {
              console.error('Token not found in tokens.json:', token);
              throw new Error('Unauthorized: Invalid user token');
            }
          
            // Verify and decode the token
            const decoded = jwt.verify(token, JWT_SECRET); // Ensure JWT_SECRET matches token creation
            console.log('Decoded token:', decoded);
          
            // Reload custodian.json to get the latest custodian data
            const custodians = loadFromFile('custodian.json');      
            // Find the custodian by email
            const custodian = custodians.find((entry) => entry.email === decoded.email);
            if (!custodian) {
              console.log(`No custodian account found for user email: ${decoded.email}`);
              return {
                message: "No custodian account created for this user",
              };
            }
          
            console.log('Custodian details retrieved successfully:', custodian);
            return custodian;
        },
        getCustodians: (_, { adminToken }) => {
            // Validate the admin token
            const decoded = validateAdminToken(adminToken);
            console.log(`Admin authorized to fetch users. Admin email: ${decoded.email}`);
          
            // Load users from users.json
            const users = loadFromFile('users.json');
            console.log('Loaded users:', users);
          
            // Return a message if no users exist
            if (!users || users.length === 0) {
              console.log('No users found in the database.');
              return {
                message: "No custodian accounts created for users",
                users: null,
              };
            }
          
            console.log('User list retrieved successfully.');
            return {
              message: null,
              users,
            };
        },
        queryAPIKey: (_, { token }) => {
            // Validate and decode the token
            const userData = validateUserToken(token);

            // Load existing API keys
            const apiKeys = loadFromFile('apikeys.json');

            // Find the API key for the user by email
            let userKey = apiKeys.find((key) => key.email === userData.email);
            if (!userKey) {
                // Create a new API key if email not found
                const apiKey = crypto.randomBytes(32).toString('hex');
                userKey = { email: userData.email, apiKey, userData };
                apiKeys.push(userKey);
                saveToFile('apikeys.json', apiKeys);
            }

            return { key: userKey.apiKey };
        },
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
        getUsers: (_, { token }) => {
          // Load the latest tokens database
          const userTokens = loadFromFile('tokens.json'); // Always fetch the latest tokens
        
          // Trim and validate the user token
          token = token.trim();
          if (!userTokens.includes(token)) {
            throw new Error('Unauthorized: Invalid or expired user token');
          }
        
          // Decode the token to get the user email
          const decoded = jwt.verify(token, JWT_SECRET);
          const userEmail = decoded.email; // Extract email from the decoded token payload
        
          // Load the latest users database
          const users = loadFromFile('users.json'); // Always fetch the latest users
        
          // Find the user corresponding to the email from the token
          const user = users.find((u) => u.email === userEmail);
          if (!user) {
            throw new Error('User not found');
          }
        
          // Return the user's information (excluding the password)
          return { ...user, password: null };
        },
        generateOTP: (_, { email }) => {
            const admins = loadFromFile('admins.json');
            const isAdmin = admins.some((a) => a.email === email);
            return generateOTP(email, isAdmin);
        },
    },       
    Mutation: {
        createUser: (_, { firstName, lastName, email, password, gender, username }) => {
            const users = loadFromFile('users.json'); // Load users dynamically
          
            // Check if the user already exists
            if (users.find((user) => user.email === email)) {
              throw new Error('User already exists');
            }
          
            // Generate the unique user ID
            const userId = generateId(); // Use "User" as the suffix
          
            // Create a new user
            const newUser = {
              id: userId,
              firstName,
              lastName,
              email,
              password,
              gender,
              username,
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            };
          
            // Add the new user to the database
            users.push(newUser);
            saveToFile('users.json', users); // Save the updated users list to the file
          
            // Return the new user (without the password)
            return { ...newUser, password: null };
        },
        createAdmin: (_, { firstName, lastName, email, password, username }) => {
            const admins = loadFromFile('admins.json'); // Load admins dynamically
          
            // Check if the admin already exists
            if (admins.find((admin) => admin.email === email)) {
              throw new Error('Admin already exists');
            }
          
            // Generate the unique admin ID
            const adminId = generateId(); // Use "Admin" as the suffix
          
            // Create a new admin
            const newAdmin = {
              id: adminId,
              firstName,
              lastName,
              email,
              username,
              password, // Consider hashing this in production
              createdAt: new Date().toISOString(),
            };
          
            // Add the new admin to the database
            admins.push(newAdmin);
            saveToFile('admins.json', admins); // Save the updated admins list to the file
          
            // Return the new admin (without the password)
            return { ...newAdmin, password: null };
        },       
        deleteUser: (_, { adminToken, userId }) => {
            validateAdminToken(adminToken); // Validate admin token
            const users = loadFromFile('users.json'); // Load users dynamically
            const deletedUsers = loadFromFile('spam.json'); // Load deleted users dynamically
      
            const userIndex = users.findIndex((user) => user.id === userId);
            if (userIndex === -1) {
              throw new Error('User not found');
            }
      
            const [removedUser] = users.splice(userIndex, 1);
            deletedUsers.push(removedUser);
      
            saveToFile('users.json', users); // Save updated users
            saveToFile('spam.json', deletedUsers); // Save updated deleted users
      
            return `User with ID ${userId} has been deleted.`;
        },
        logout: (_, { token }) => {
            const userTokens = loadFromFile('tokens.json'); // Fetch the latest user tokens
            const adminTokens = loadFromFile('adtokens.json'); // Fetch the latest admin tokens
          
            if (userTokens.includes(token)) {
              const updatedUserTokens = userTokens.filter((t) => t !== token);
              saveToFile('tokens.json', updatedUserTokens); // Save updated user tokens
              return 'Successfully logged out';
            }
          
            if (adminTokens.includes(token)) {
              const updatedAdminTokens = adminTokens.filter((t) => t !== token);
              saveToFile('adtokens.json', updatedAdminTokens); // Save updated admin tokens
              return 'Successfully logged out';
            }
          
            throw new Error('Invalid or expired token');
        }, 
        createCustodian: async (_, { token }) => {
            // Validate the user token
            const decoded = validateUserToken(token);
            console.log(`Creating custodian for user with email: ${decoded.email}`);
          
            // Load users from users.json
            const users = loadFromFile('users.json');
          
            // Find the user by email from the decoded token
            const user = users.find((user) => user.email === decoded.email);
            if (!user) {
              console.error('User not found for token email:', decoded.email);
              throw new Error('Unauthorized: User does not exist');
            }
          
            // Reload the custodians file to ensure it's up to date
            const custodians = loadFromFile('custodian.json');
          
            // Check if a custodian already exists for this user
            const custodianExists = custodians.find((entry) => entry.email === user.email);
            if (custodianExists) {
              throw new Error('Custodian already exists for this user');
            }
          
            // Generate wallet addresses
            const bscAddress = generateBscWalletAddress();
            const solanaAddress = generateSolanaWalletAddress();
            const tonAddress = await generateTonWalletAddress();
            const ambAddress = generateAmbWalletAddress();
          
            // Create a new custodian record
            const newCustodian = {
              userId: user.id,
              email: user.email, // Use the email from users.json
              token, // Save the token for reference
              bsc: bscAddress,
              solana: solanaAddress,
              ton: tonAddress,
              amb: ambAddress,
            };
          
            // Add the new custodian to the list and save it
            custodians.push(newCustodian);
            saveToFile('custodian.json', custodians);
          
            console.log('New custodian created successfully for user:', user.email);
            return newCustodian;
        },      
        adminSignOut: (_, { adminToken }) => {
            // Load the latest admin tokens from adtokens.json
            const adminTokens = loadFromFile('adtokens.json');
            console.log('Current admin tokens in adtokens.json:', adminTokens);
            
            // Validate if the provided adminToken exists in the file
            if (!adminTokens.includes(adminToken)) {
                console.error('Admin token not found in adtokens.json:', adminToken);
                throw new Error('Unauthorized: Admin token not found or already revoked');
            }
            
            // Verify the token using ADMIN_SECRET
            const decoded = jwt.verify(adminToken, ADMIN_SECRET); // Ensure ADMIN_SECRET matches the signing key
            console.log(`Admin token validated successfully. Admin email: ${decoded.email}`);
            
            // Remove the admin token from the list
            const updatedTokens = adminTokens.filter((token) => token !== adminToken);
            
            // Save the updated token list back to adtokens.json
            saveToFile('adtokens.json', updatedTokens);
            console.log('Admin token revoked and removed from adtokens.json');
            
            // Return a success message
            return {
                message: "Admin token revoked successfully. It is no longer valid.",
            };
        },
        generateAPIKey: (_, { token }) => {
            // Validate and decode the token
            const userData = validateUserToken(token);

            // Load existing API keys
            const apiKeys = loadFromFile('apikeys.json');

            // Check if an API key already exists for the user by email
            let userKey = apiKeys.find((key) => key.email === userData.email);
            if (userKey) {
                throw new Error('API key already exists for this user. Revoke the existing key to generate a new one.');
            }

            // Generate a random API key
            const apiKey = crypto.randomBytes(32).toString('hex');

            // Save the new API key with user email
            userKey = { email: userData.email, apiKey, userData };
            apiKeys.push(userKey);
            saveToFile('apikeys.json', apiKeys);

            return { key: apiKey };
        },
        revokeAPIKey: (_, { token }) => {
            // Validate and decode the token
            const userData = validateUserToken(token);

            // Load existing API keys
            const apiKeys = loadFromFile('apikeys.json');

            // Find and remove the existing API key by email
            const existingKeyIndex = apiKeys.findIndex((key) => key.email === userData.email);
            if (existingKeyIndex === -1) {
                throw new Error('No existing API key found for this user to revoke.');
            }

            apiKeys.splice(existingKeyIndex, 1);

            // Generate a new API key
            const newApiKey = crypto.randomBytes(32).toString('hex');

            // Save the new API key with user email
            const newUserKey = { email: userData.email, apiKey: newApiKey, userData };
            apiKeys.push(newUserKey);
            saveToFile('apikeys.json', apiKeys);

            return { key: newApiKey };
        },
        createSuperKey: (_, { adminToken }) => {
            // Validate and decode the admin token
            const adminData = validateAdminToken(adminToken);

            // Load existing super keys
            const superKeys = loadFromFile('superkeys.json');

            // Generate a new Super API key
            const superApiKey = crypto.randomBytes(64).toString('hex');

            // Save the new super key with admin email
            const superKeyEntry = { email: adminData.email, superApiKey };
            superKeys.push(superKeyEntry);
            saveToFile('superkeys.json', superKeys);

            return { key: superApiKey };
        },
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
        
                if (payment.status === 'Started') {
                    console.log(`Payment already started for ID: ${id}`);
                    return {
                        paymentLink: `https://payment-platform.com/pay/${id}`,
                        status: 'Started',
                        message: 'A payment has already been started for this link.',
                    };
                }
        
                // Find the recipient address based on the chosen blockchain
                const recipientAddressEntry = payment.recipientAddresses.find(
                    (entry) => entry.blockchain === blockchain
                );
        
                if (!recipientAddressEntry) {
                    console.error(`No recipient address found for blockchain: ${blockchain} and ID: ${id}`);
                    throw new Error(`No recipient address found for blockchain: ${blockchain}`);
                }
        
                const recipientAddress = recipientAddressEntry.address;
        
                // Generate wallet address depending on the blockchain
                let walletAddress, privateKey, convertedAmount;
                if (blockchain === 'AMB') {
                    const wallet = ethers.Wallet.createRandom();
                    walletAddress = wallet.address;
                    privateKey = wallet.privateKey;
                    const livePrice = await fetchLivePrice(blockchain);
                    convertedAmount = payment.amount / livePrice;
                } else if (blockchain === 'BSC') {
                    const account = web3.eth.accounts.create();
                    walletAddress = account.address;
                    privateKey = account.privateKey;
                    const livePrice = await fetchLivePrice(blockchain);
                    convertedAmount = payment.amount / livePrice;
                } else if (blockchain === 'Solana') {
                    const keypair = Keypair.generate();
                    walletAddress = keypair.publicKey.toBase58();
                    privateKey = Buffer.from(keypair.secretKey).toString('hex');
                    const livePrice = await fetchLivePrice(blockchain);
                    convertedAmount = payment.amount / livePrice;
                } else if (blockchain === 'TON') {
                    const keyPair = TonWeb.utils.newKeyPair();
                    const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, { publicKey: keyPair.publicKey, wc: 0 });
                    walletAddress = (await wallet.getAddress()).toString(true, true, false); // UQ format
                    privateKey = TonWeb.utils.bytesToHex(keyPair.secretKey);
                    const livePrice = await fetchLivePrice(blockchain);
                    convertedAmount = payment.amount / livePrice;
                } else {
                    console.error(`Unsupported blockchain: ${blockchain} for ID: ${id}`);
                    throw new Error('Unsupported blockchain');
                }
        
                // Update the payment status to 'Started'
                payment.status = 'Started';
                const updatedPayment = {
                    ...payment,
                    walletAddress,
                    privateKey,
                    convertedAmount,
                    recipientAddress,
                    startedAt: new Date().toISOString(),
                };
        
                saveToFile(paymentLinkFilePath, paymentLinks);
        
                // Save to linkpay.json
                startedPayments.push(updatedPayment);
                saveToFile(path.join(__dirname, 'linkpay.json'), startedPayments);
        
                // Monitor the payment for completion
                monitorPayment(updatedPayment, id);
        
                return {
                    id: payment.id,
                    walletAddress,
                    privateKey,
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
                console.error(`Error starting payment link for ID: ${id}`, error);
                throw new Error('An error occurred while starting the payment.');
            }
        },
        changeUserPassword: (_, { token, otp, oldPassword, newPassword }) => {
            const users = loadFromFile('users.json');
            if (!token && !otp) {
              throw new Error('Either token or OTP must be provided');
            }
      
            let user;
            if (token) {
              const decoded = validateUserToken(token);
              user = users.find((u) => u.id === decoded.id);
              if (!user) {
                throw new Error('Invalid token or user not found');
              }
      
              if (oldPassword && user.password !== oldPassword) {
                throw new Error('Old password is incorrect');
              }
            }
      
            if (otp) {
              const otpData = otpStore[otp];
              if (!otpData || new Date() > new Date(otpData.expiry) || otpData.type !== 'user') {
                throw new Error('Invalid or expired OTP');
              }
              user = users.find((u) => u.id === otpData.id);
              if (!user) {
                throw new Error('Invalid OTP or user not found');
              }
      
              // Invalidate OTP after use
              delete otpStore[otp];
            }
      
            if (!user) {
              throw new Error('Unable to locate user');
            }
      
            user.password = newPassword;
            saveToFile('users.json', users);
            return 'User password changed successfully';
          },
        changeAdminPassword: (_, { adminToken, otp, oldPassword, newPassword }) => {
            const admins = loadFromFile('admins.json');
            if (!adminToken && !otp) {
              throw new Error('Either adminToken or OTP must be provided');
            }
      
            let admin;
            if (adminToken) {
              const decoded = validateAdminToken(adminToken);
              admin = admins.find((a) => a.id === decoded.id);
              if (!admin) {
                throw new Error('Invalid token or admin not found');
              }
      
              if (oldPassword && admin.password !== oldPassword) {
                throw new Error('Old password is incorrect');
              }
            }
      
            if (otp) {
              const otpData = otpStore[otp];
              if (!otpData || new Date() > new Date(otpData.expiry) || otpData.type !== 'admin') {
                throw new Error('Invalid or expired OTP');
              }
              admin = admins.find((a) => a.id === otpData.id);
              if (!admin) {
                throw new Error('Invalid OTP or admin not found');
              }
      
              // Invalidate OTP after use
              delete otpStore[otp];
            }
      
            if (!admin) {
              throw new Error('Unable to locate admin');
            }
      
            admin.password = newPassword;
            saveToFile('admins.json', admins);
            return 'Admin password changed successfully';
        },
        changeUserEmail: (_, { token, otp, newEmail }) => {
            const users = loadFromFile('users.json');
            if (!token || !otp) {
              throw new Error('Both token and OTP must be provided');
            }
      
            const decoded = validateUserToken(token);
            const user = users.find((u) => u.id === decoded.id);
            if (!user) {
              throw new Error('Invalid token or user not found');
            }
      
            const otpData = otpStore[otp];
            if (!otpData || new Date() > new Date(otpData.expiry) || otpData.type !== 'user' || otpData.id !== user.id) {
              throw new Error('Invalid or expired OTP');
            }
      
            if (!newEmail || !newEmail.includes('@')) {
              throw new Error('A valid email address must be provided');
            }
      
            user.email = newEmail;
            saveToFile('users.json', users);
      
            // Invalidate OTP after use
            delete otpStore[otp];
      
            return 'User email changed successfully';
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

// Create the Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Enables introspection for Apollo Studio
});

(async () => {
  const { url } = await startStandaloneServer(server, {
    listen: { port: process.env.PORT || 4000 }, // Use the platform's assigned port or default to 4001
  });

  console.log(`\uD83D\uDE80 Server ready at ${url}`);
})();
