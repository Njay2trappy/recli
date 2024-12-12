const { printSchema } = require('graphql');
const { ApolloServer, gql } = require('apollo-server');
const fs = require('fs');

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

const resolvers = {};

const server = new ApolloServer({ typeDefs, resolvers });

fs.writeFileSync('./schema.graphql', printSchema(server.schema));

console.log('Schema generated at ./schema.graphql');
