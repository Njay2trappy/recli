const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const axios = require('axios');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const Web3 = require('web3');
const { Keypair, Connection, clusterApiUrl, SystemProgram, Transaction, PublicKey } = require('@solana/web3.js');
const TonWeb = require('tonweb');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');

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


// Define the GraphQL schema
const typeDefs = gql`
    type Query {
        login(email: String!, password: String!): AuthPayload!
        adminLogin(email: String!, password: String!): AdminAuthPayload!
        getAllUsers(adminToken: String): [User!]!
        getDeletedUsers(adminToken: String): [User!]!
        getTokens(adminToken: String!): [String!]!
        getWalletAddresses(token: String!): CustodianOrMessage!
        getUsers(adminToken: String!): UsersOrMessage!
        queryAPIKey(token: String!): APIKey!
        getPayment(adminToken: String!): [Payment]
        getPaymentsByUser(userToken: String, apiKey: String): [Payment]
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
`;

// Secret for JWT
const JWT_SECRET = 'supersecretkey';
const ADMIN_SECRET = 'adminsecretkey';

const paymentsFilePath = path.join(__dirname, 'payments.json');

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


// Mock database
const users = [];
const admins = [];
const activeTokens = new Set();
const tokensFile = 'tokens.json';

const saveTokensToFile = () => {
    const userTokens = [...activeTokens].filter((token) => {
      const decoded = jwt.decode(token);
      return decoded && decoded.id && decoded.email && !decoded.admin;
    });
  
    const adminTokens = [...activeTokens].filter((token) => {
      const decoded = jwt.decode(token);
      return decoded && decoded.id && decoded.email && decoded.admin;
    });
  
    fs.writeFileSync(tokensFile, JSON.stringify(userTokens, null, 2));
    fs.writeFileSync('adtokens.json', JSON.stringify(adminTokens, null, 2));
  };
  

const loadTokensFromFile = () => {
  if (fs.existsSync(tokensFile)) {
    return new Set(JSON.parse(fs.readFileSync(tokensFile)));
  }
  return new Set();
};

activeTokens.add(...loadTokensFromFile());

const revokeToken = (token) => {
  activeTokens.delete(token);
  saveTokensToFile();
};

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

// Helper function to validate token
const validateToken = (token, secret) => {
  if (!activeTokens.has(token)) {
    throw new Error('Token is invalid or has expired');
  }

  try {
    return jwt.verify(token, secret);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      activeTokens.delete(token);
      saveTokensToFile();
      if (secret === ADMIN_SECRET) {
        fs.writeFileSync('adtokens.json', JSON.stringify([...activeTokens], null, 2));
      }
      throw new Error('Token has expired');
    }
    throw new Error('Token is invalid');
  }
};


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

// Helper to generate random wallet addresses
const generateBscWalletAddress = () => {
  const web3 = new Web3('https://bsc-dataseed.binance.org/'); // Add BSC provider
  const account = web3.eth.accounts.create();
  return account.address;
};

const generateSolanaWalletAddress = () => {
  const keypair = Keypair.generate();
  return keypair.publicKey.toBase58();
};

const generateTonWalletAddress = async () => {
    try {
        // Generate a new key pair
        const keyPair = TonWeb.utils.newKeyPair();

        // Initialize the wallet with the generated public key
        const tonweb = new TonWeb(new TonWeb.HttpProvider('https://testnet.toncenter.com/api/v2/jsonRPC', {
          apiKey: '8723f42a9a980ba38692832aad3d42fcbe0f0435600c6cd03d403e800bdd2e88'
        }));
        const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, {
            publicKey: keyPair.publicKey,
            wc: 0, // Workchain ID (0 is the standard workchain)
        });

        // Generate the wallet address in UQ format
        const walletAddress = (await wallet.getAddress()).toString(true, true, false);

        return {
            walletAddress,
            privateKey: TonWeb.utils.bytesToHex(keyPair.secretKey),
        };
    } catch (error) {
        console.error('Error generating TON wallet address:', error);
        throw new Error('Failed to generate TON wallet address');
    }
};

const generateAmbWalletAddress = () => {
    try {
        // Generate a random wallet
        const wallet = ethers.Wallet.createRandom();

        return {
            walletAddress: wallet.address,
            privateKey: wallet.privateKey,
        };
    } catch (error) {
        console.error('Error generating AMB wallet address:', error);
        throw new Error('Failed to generate AMB wallet address');
    }
};


const deletedUsers = [];
const saveUsersToFile = () => {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
};
const saveDeletedUsersToFile = () => {
  fs.writeFileSync('spam.json', JSON.stringify(deletedUsers, null, 2));
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

// Load users and deleted users on start
Object.assign(users, loadUsersFromFile());
Object.assign(deletedUsers, loadDeletedUsersFromFile());

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
            const user = users.find((user) => user.email === email);
            if (!user) {
                throw new Error('User not found');
            }

            if (user.password !== password) {
                throw new Error('Invalid password');
            }

            const existingToken = [...activeTokens].find((token) => {
                try {
                const decoded = jwt.decode(token);
                return decoded?.email === email;
                } catch {
                return false;
                }
            });
            

            if (existingToken) {
                throw new Error('User is already logged in');
            }

            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
                expiresIn: '1h',
            });

            activeTokens.add(token);
            saveTokensToFile();

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

            const existingToken = [...activeTokens].find((token) => {
                const decoded = jwt.decode(token);
                return decoded?.email === email;
            });

            if (existingToken) {
                throw new Error('Admin is already logged in');
            }

            const adminToken = jwt.sign({ id: admin.id, email: admin.email }, ADMIN_SECRET, {
                expiresIn: '1h',
            });

            activeTokens.add(adminToken);
            fs.writeFileSync('adtokens.json', JSON.stringify([...activeTokens], null, 2)); // Save admin tokens

            return { adminToken, admin };
    },
    getAllUsers: (_, { adminToken }, context) => {
            const token = adminToken || context.token;
            if (!token) {
                throw new Error('Admin token is required');
            }
            
            // Load admin tokens from the database
            const adminTokens = new Set(JSON.parse(fs.readFileSync('adtokens.json')));
            
            // Check if the token is valid
            if (!adminTokens.has(token)) {
                throw new Error('Invalid or expired admin token');
            }
            
            const admin = validateToken(token, ADMIN_SECRET); // Validate the admin token
            return users.map((user) => ({ ...user, password: null }));
    },
    
    getDeletedUsers: (_, { adminToken }, context) => {
            const token = adminToken || context.token;
            if (!token) {
                throw new Error('Admin token is required');
            }
            
            // Load admin tokens from the database
            const adminTokens = new Set(JSON.parse(fs.readFileSync('adtokens.json')));
            
            // Check if the token is valid
            if (!adminTokens.has(token)) {
                throw new Error('Invalid or expired admin token');
            }
            
            const admin = validateToken(token, ADMIN_SECRET); // Validate the admin token
            return deletedUsers;
    },
    getTokens: (_, { adminToken }) => {
            // Validate the admin token
            validateToken(adminToken, ADMIN_SECRET);
            
            // Load all user tokens from tokens.json
            const userTokens = JSON.parse(fs.readFileSync('tokens.json'));
            
            if (!Array.isArray(userTokens)) {
                throw new Error('Invalid token storage format');
            }
            
            // Return the list of user tokens
            return userTokens;
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
    getUsers: (_, { adminToken }) => {
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

            // Find the API key for the user
            const userKey = apiKeys.find((key) => key.userId === userData.userId);
            if (!userKey) {
                throw new Error('API key not found for the provided token.');
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
    },
  Mutation: {
    createUser: (_, { firstName, lastName, email, password, gender, username }) => {
        if (users.find((user) => user.email === email)) {
            throw new Error('User already exists');
        }

        const newUser = {
            id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,        firstName,
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
            id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,        firstName,
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
    deleteUser: (_, { adminToken, userId }, context) => {
        const token = adminToken || context.token;
        if (!token) {
            throw new Error('Admin token is required');
        }

        const admin = validateToken(token, ADMIN_SECRET);
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
    logout: (_, { token }) => {
            // Load tokens from the appropriate file
            const userTokens = new Set(JSON.parse(fs.readFileSync('tokens.json')));
            const adminTokens = new Set(JSON.parse(fs.readFileSync('adtokens.json')));
        
            // Check if the token is valid in either users or admins
            if (!userTokens.has(token) && !adminTokens.has(token)) {
            throw new Error('Invalid or expired token');
            }
        
            // Remove the token from the respective set
            if (userTokens.has(token)) {
            userTokens.delete(token);
            fs.writeFileSync('tokens.json', JSON.stringify([...userTokens], null, 2));
            } else if (adminTokens.has(token)) {
            adminTokens.delete(token);
            fs.writeFileSync('adtokens.json', JSON.stringify([...adminTokens], null, 2));
            }
        
            return 'Successfully logged out';
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

            // Check if an API key already exists for the user
            const existingKeyIndex = apiKeys.findIndex((key) => key.userId === userData.userId);
            if (existingKeyIndex !== -1) {
                throw new Error('API key already exists. Revoke the existing key to generate a new one.');
            }

            // Generate a random API key
            const apiKey = crypto.randomBytes(32).toString('hex');

            // Save the new API key along with the user data
            apiKeys.push({ userId: userData.userId, apiKey, userData });
            saveToFile('apikeys.json', apiKeys);

            return { key: apiKey };
        },
        revokeAPIKey: (_, { token }) => {
            // Validate and decode the token
            const userData = validateUserToken(token);

            // Load existing API keys
            const apiKeys = loadFromFile('apikeys.json');

            // Find and remove the existing API key
            const existingKeyIndex = apiKeys.findIndex((key) => key.userId === userData.userId);
            if (existingKeyIndex === -1) {
                throw new Error('No existing API key found to revoke.');
            }

            apiKeys.splice(existingKeyIndex, 1);

            // Generate a new API key
            const newApiKey = crypto.randomBytes(32).toString('hex');

            // Save the new API key along with the user data
            apiKeys.push({ userId: userData.userId, apiKey: newApiKey, userData });
            saveToFile('apikeys.json', apiKeys);

            return { key: newApiKey };
        },
        createSuperKey: (_, { adminToken }) => {
            // Validate and decode the admin token
            validateAdminToken(adminToken);

            // Load existing super keys
            const superKeys = loadFromFile('superkeys.json');

            // Generate a new Super API key
            const superApiKey = crypto.randomBytes(64).toString('hex');

            // Save the new super key to superkeys.json
            superKeys.push({ superApiKey });
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
        }
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
    // Deduct a fee (e.g., 0.01 TON for transaction cost)
    const fee = 10_000_000; // 0.01 TON in nanotons
    const amountToSend = nanotons - fee;

    if (amountToSend <= 0) {
      console.log('Insufficient funds after deducting transaction fee.');
      return;
    }

    // Reuse the previously generated public key and private key
    const secretKeyBytes = TonWeb.utils.hexToBytes(privateKey); // Convert private key from hex to bytes
    const publicKeyBytes = secretKeyBytes.slice(32); // Extract public key from the last 32 bytes of the private key

    // Initialize the wallet using the saved public key
    const wallet = new tonweb.wallet.all.v3R2(tonweb.provider, {
      publicKey: publicKeyBytes, // Use the public key bytes
      wc: 0, // Workchain ID (0 is the standard workchain)
    });

    // Set seqno explicitly to 0 for the first transaction
    const seqno = 0;

    // Transfer funds to the recipient address
    await wallet.methods
      .transfer({
        secretKey: secretKeyBytes, // Use the private key bytes
        toAddress: recipientAddress,
        amount: amountToSend, // Amount after deducting fee
        seqno: seqno, // Explicitly set to 0
        sendMode: 3,
      })
      .send();

    console.log(`Transferred ${amountToSend / 1e9} TON to recipient address: ${recipientAddress}`);
  } catch (error) {
      console.error('Error transferring TON funds:', error.message || error);
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

// Create the Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Enables introspection for Apollo Studio
  context: ({ req }) => {
    const token = req.headers.authorization || null;
    return { token };
  },
});

(async () => {
  const { url } = await startStandaloneServer(server, {
    listen: { port: process.env.PORT || 4002 }, // Use the platform's assigned port or default to 4001
  });

  console.log(`\uD83D\uDE80 Server ready at ${url}`);
})();
