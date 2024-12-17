const { printSchema } = require('graphql');
const { ApolloServer, gql } = require('apollo-server');
const { buildSubgraphSchema } = require('@apollo/subgraph'); // Optional for subgraphs
const fs = require('fs');

// Define your GraphQL schema
const typeDefs = gql`
    directive @example on FIELD_DEFINITION
    
    type Query {
        getPaymentDetailsLink(id: ID!): PaymentLink
        getLinkedPayments(apiKey: String!): [StartedPayment!]!
        generateOTP(email: String!): OTPResponse!
    }
    type Mutation {
        generatePaymentLink(apiKey: String!, amount: Float!): PaymentLinkResponse
        startPaymentLink(id: ID!, blockchain: String!): PaymentDetails
        changeUserPassword(token: String, otp: String, oldPassword: String, newPassword: String!): String!
        changeAdminPassword(adminToken: String, otp: String, oldPassword: String, newPassword: String!): String!
        changeUserEmail(token: String, otp: String, newEmail: String!): String!
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
