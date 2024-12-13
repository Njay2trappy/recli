const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const jwt = require('jsonwebtoken');

// Secrets for JWT
const JWT_SECRET = 'adminsecretkey';
const ADMIN_SECRET = 'adminsecretkey';

// Define the GraphQL schema
const typeDefs = gql`
  type Query {
    getBalance(token: String!): Float!
    getTransactions(token: String!): [Transaction!]!
    getAllTransactions(adminToken: String!): [Transaction!]!
  }

  type Mutation {
    updateTransactionStatus(adminToken: String!, transactionId: ID!, status: String!): Transaction!
    topUpAccount(adminToken: String!, username: String!, amount: Float!): Transaction!
  }

  type Transaction {
    id: ID!
    userid: ID!
    walletAddress: String!
    privateKey: String!
    amount: Float!
    convertedAmount: Float!
    status: String! # "success", "pending", "failed"
    createdAt: String!
    blockchain: String!
  }

  type User {
    id: ID!
    firstName: String!
    lastName: String!
    email: String!
  }

  type Admin {
    id: ID!
    username: String!
    email: String!
  }
`;

// Mock databases
const users = JSON.parse(fs.readFileSync('users.json', 'utf8')) || [];
const admins = JSON.parse(fs.readFileSync('admins.json', 'utf8')) || [];
const transactions = JSON.parse(fs.readFileSync('usertransactions.json', 'utf8')) || [];

const saveTransactionsToFile = () => {
  fs.writeFileSync('usertransactions.json', JSON.stringify(transactions, null, 2));
};

// Resolver functions
const resolvers = {
  Query: {
    getBalance: (_, { token }) => {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = users.find((u) => u.id === decoded.id);

      if (!user) {
        throw new Error('Invalid token or user not found');
      }

      // Calculate balance from transactions
      const userTransactions = transactions.filter((t) => t.userid === user.id && t.status === 'success');
      const balance = userTransactions.reduce((sum, t) => sum + (t.type === 'deposit' ? t.amount : -t.amount), 0);

      return balance;
    },

    getTransactions: (_, { token }) => {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = users.find((u) => u.id === decoded.id);

      if (!user) {
        throw new Error('Invalid token or user not found');
      }

      return transactions.filter((t) => t.userid === user.id);
    },

    getAllTransactions: (_, { adminToken }) => {
      const decoded = jwt.verify(adminToken, ADMIN_SECRET);
      const admin = admins.find((a) => a.id === decoded.id);

      if (!admin) {
        throw new Error('Invalid admin token or admin not found');
      }

      return transactions;
    },
  },

  Mutation: {
    updateTransactionStatus: (_, { adminToken, transactionId, status }) => {
      const decoded = jwt.verify(adminToken, ADMIN_SECRET);
      const admin = admins.find((a) => a.id === decoded.id);

      if (!admin) {
        throw new Error('Invalid admin token or admin not found');
      }

      const transaction = transactions.find((t) => t.id === transactionId);
      if (!transaction) {
        throw new Error('Transaction not found');
      }

      transaction.status = status;
      saveTransactionsToFile();
      return transaction;
    },

    topUpAccount: (_, { adminToken, username, amount }) => {
      const decoded = jwt.verify(adminToken, ADMIN_SECRET);
      const admin = admins.find((a) => a.id === decoded.id);

      if (!admin) {
        throw new Error('Invalid admin token or admin not found');
      }

      const user = users.find((u) => u.username === username);
      if (!user) {
        throw new Error('User not found');
      }

      const newTransaction = {
        id: (transactions.length + 1).toString(),
        userid: user.id,
        walletAddress: "GeneratedWalletAddress", // Replace with logic for wallet address
        privateKey: "GeneratedPrivateKey", // Replace with logic for private key
        amount,
        convertedAmount: amount * 1, // Replace with conversion logic if necessary
        status: 'success',
        createdAt: new Date().toISOString(),
        blockchain: 'BSC', // Or Solana, based on logic
      };

      transactions.push(newTransaction);
      saveTransactionsToFile();
      return newTransaction;
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
