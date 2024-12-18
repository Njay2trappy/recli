const { printSchema } = require('graphql');
const { ApolloServer, gql } = require('apollo-server');
const { buildSubgraphSchema } = require('@apollo/subgraph'); // Optional for subgraphs
const fs = require('fs');

// Define your GraphQL schema
const typeDefs = gql`
    directive @example on FIELD_DEFINITION
    
    type Query {
        getUsers(token: String!): User!
        getCustodians(adminToken: String!): UsersOrMessage!
    }
    type UsersOrMessage {
        message: String
        users: [User!]
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
