const { printSchema } = require('graphql');
const { ApolloServer, gql } = require('apollo-server');
const { buildSubgraphSchema } = require('@apollo/subgraph'); // Optional for subgraphs
const fs = require('fs');

// Define your GraphQL schema
const typeDefs = gql`
    directive @example on FIELD_DEFINITION
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

// Define resolvers (optional for schema generation)
const resolvers = {};  
// Use buildSubgraphSchema if working with Apollo Federation, otherwise just use typeDefs
const schema = buildSubgraphSchema
    ? buildSubgraphSchema({ typeDefs, resolvers })
    : new ApolloServer({ typeDefs, resolvers }).schema;

// Log and save the schema
try {
    if (!schema) {
        throw new Error("Schema is undefined. Ensure ApolloServer is properly initialized.");
    }

    // Log directives if available
    const directives = schema.getDirectives ? schema.getDirectives() : [];
    console.log("Directives:", directives.map((directive) => directive.name));

    // Write the schema to a file
    const schemaFilePath = './products-schema.graphql';
    fs.writeFileSync(schemaFilePath, printSchema(schema));
    console.log(`Schema successfully written to ${schemaFilePath}`);
} catch (error) {
    console.error("Error generating schema:", error.message);
}
