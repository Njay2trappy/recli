const { ApolloServer, gql } = require('apollo-server');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Secrets for JWT verification
const JWT_SECRET = 'supersecretkey';
const ADMIN_SECRET = 'adminsecretkey';

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

// Validate and decode the user token
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

// Validate and decode the admin token
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

// Type definitions (Schema)
const typeDefs = gql`
    type APIKey {
        key: String!
    }

    type Query {
        queryAPIKey(token: String!): APIKey!
    }

    type Mutation {
        generateAPIKey(token: String!): APIKey!
        revokeAPIKey(token: String!): APIKey!
        createSuperKey(adminToken: String!): APIKey!
    }
`;

// Resolvers
const resolvers = {
    Query: {
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
    },
    Mutation: {
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
    },
};

// Create an Apollo Server instance
const server = new ApolloServer({
    typeDefs,
    resolvers,
});

// Start the server
server.listen().then(({ url }) => {
    console.log(`🚀 Server ready at ${url}`);
});
