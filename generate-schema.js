const { printSchema } = require('graphql');
const { ApolloServer, gql } = require('apollo-server');
const fs = require('fs');

// Define your GraphQL schema (typeDefs)
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

// Define resolvers (optional, not required for schema generation)
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

// Create Apollo Server instance
const server = new ApolloServer({
    typeDefs,
    resolvers,
});

// Generate the schema file
fs.writeFileSync('./schema.graphql', printSchema(server.schema));

console.log('Schema has been successfully generated and saved to schema.graphql');
