const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const crypto = require('crypto');
const Web3 = require('web3');
const { Keypair } = require('@solana/web3.js');

// Define the GraphQL schema
const typeDefs = gql`
  type Query {
    getDeposits(userId: ID!): [Deposit!]!
    getWalletAddresses(userId: ID!, blockchain: String!): WalletAddresses!
    getUsers: [User!]!
    getUserById(userId: ID!): User!
  }

  type Mutation {
    createDeposit(userId: ID!, amount: Float!): Deposit!
    createCustodian(username: String!, token: String!): Custodian!
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

  type User {
    id: ID!
    firstName: String!
    lastName: String!
    email: String!
  }
`;


// Mock database
const deposits = [];
const custodians = [];
// Load users from users.json
const loadUsersFromFile = () => {
    if (fs.existsSync('users.json')) {
      return JSON.parse(fs.readFileSync('users.json'));
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

// Load data on start
Object.assign(deposits, loadDepositsFromFile());
Object.assign(custodians, loadCustodiansFromFile());

// Helper to generate random wallet addresses
const generateBscWalletAddress = () => {
  const web3 = new Web3();
  const account = web3.eth.accounts.create();
  return account.address;
};

const generateSolanaWalletAddress = () => {
  const keypair = Keypair.generate();
  return keypair.publicKey.toBase58();
};

// Resolver functions
const resolvers = {
    Query: {
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
  
// Create the Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Enables introspection for Apollo Studio
});

(async () => {
  const { url } = await startStandaloneServer(server, {
    listen: { port: process.env.PORT || 4001 }, // Use the platform's assigned port or default to 4001
  });

  console.log(`\uD83D\uDE80 Server ready at ${url}`);
})();
