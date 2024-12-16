const { printSchema } = require('graphql');
const { ApolloServer, gql } = require('apollo-server');
const { buildSubgraphSchema } = require('@apollo/subgraph'); // Optional for subgraphs
const fs = require('fs');

// Define your GraphQL schema
const typeDefs = gql`
    directive @example on FIELD_DEFINITION
    
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
