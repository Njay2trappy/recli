const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const Web3 = require('web3');
const { Keypair } = require('@solana/web3.js');
const TonWeb = require('tonweb');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');

// Utility functions to read/write files
const loadFromFile = (filename) => {
    if (fs.existsSync(filename)) {
      return JSON.parse(fs.readFileSync(filename));
    }
    return [];
};
  
const saveToFile = (filename, data) => {
    fs.writeFileSync(filename, JSON.stringify(data, null, 2));
};

// Define GraphQL schema
const typeDefs = gql`
    type Query {
        getWalletAddresses(token: String!): CustodianOrMessage!
        getUsers(adminToken: String!): UsersOrMessage!
    }

    type Mutation {
        createCustodian(token: String!): CustodianOrMessage!
        adminSignOut(adminToken: String!): Message!
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
    type User {
        id: ID
        firstName: String
        lastName: String
        email: String
        password: String
        gender: String
        username: String
        createdAt: String
        updatedAt: String
    }
`;

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
      console.error('Token validation error:', err.message);
      throw new Error('Unauthorized: Invalid or expired user token');
    }
};


const validateAdminToken = (adminToken) => {
    try {
      console.log('Validating admin token:', adminToken);
  
      // Reload admin tokens from adtokens.json
      const adminTokens = loadFromFile('adtokens.json');
      console.log('Admin tokens in adtokens.json:', adminTokens);
  
      // Trim the token to avoid formatting issues
      adminToken = adminToken.trim();
  
      // Check if the token exists in adtokens.json
      if (!adminTokens.includes(adminToken)) {
        console.error('Admin token not found in adtokens.json:', adminToken);
        throw new Error('Unauthorized: Invalid admin token');
      }
  
      // Decode and verify the admin token
      const decoded = jwt.verify(adminToken, ADMIN_SECRET); // Ensure ADMIN_SECRET matches the signing key
      console.log('Admin token decoded successfully:', decoded);
  
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

// Resolvers
const resolvers = {
  Query: {
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
  },
  Mutation: {
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
  },
};

// Apollo Server Initialization
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
});

(async () => {
  const { url } = await startStandaloneServer(server, {
    listen: { port: process.env.PORT || 4001 },
  });

  console.log(`🚀 Server ready at ${url}`);
})();
