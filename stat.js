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
    }

    type Mutation {
        generatePaymentAddress(userId: String!, amount: Float!, blockchain: String!): Payment
    }
`;

// Define resolvers (optional for schema generation)
const resolvers = {
    Query: {
        getPayment: (_, { id }) => {
            const payments = readPayments();
            return payments.find(payment => payment.id === id) || null;
        },
        getPaymentsByUser: (_, { userId }) => {
            const payments = readPayments();
            return payments.filter(payment => payment.userId === userId);
        },
    },
    Mutation: {
        generatePaymentAddress: async (_, { userId, amount, blockchain }) => {
            const payments = readPayments();
            let walletAddress, privateKey;

            // Generate wallet address
            if (blockchain === 'BSC') {
                const account = web3.eth.accounts.create();
                walletAddress = account.address;
                privateKey = account.privateKey;
            } else if (blockchain === 'Solana') {
                const keypair = Keypair.generate();
                walletAddress = keypair.publicKey.toBase58();
                privateKey = Buffer.from(keypair.secretKey).toString('hex');
            } else {
                throw new Error('Unsupported blockchain');
            }

            // Fetch live conversion rate and calculate converted amount
            const livePrice = await fetchLivePrice(blockchain);
            const convertedAmount = amount / livePrice;

            const newPayment = {
                id: uuidv4(),
                userId,
                walletAddress,
                privateKey,
                amount,
                convertedAmount,
                status: 'Pending',
                createdAt: new Date().toISOString(),
                blockchain,
            };

            payments.push(newPayment);
            writePayments(payments);

            monitorPayment(newPayment);

            return newPayment;
        },
    },
};

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
