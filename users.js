const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const jwt = require('jsonwebtoken');

// Define the GraphQL schema
const typeDefs = gql`
  type Query {
    login(email: String!, password: String!): AuthPayload!
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

  type AuthPayload {
    token: String!
    user: User!
  }
`;

// Mock database
const users = [];
const saveUsersToFile = () => {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
};
const loadUsersFromFile = () => {
  if (fs.existsSync('users.json')) {
    return JSON.parse(fs.readFileSync('users.json'));
  }
  return [];
};

// Load users on start
Object.assign(users, loadUsersFromFile());

// Secret for JWT
const JWT_SECRET = 'supersecretkey';

// Resolver functions
const resolvers = {
  Query: {
    login: (_, { email, password }) => {
      const user = users.find((user) => user.email === email);
      if (!user) {
        throw new Error('User not found');
      }

      if (user.password !== password) {
        throw new Error('Invalid password');
      }

      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: '1h',
      });

      return { token, user };
    },
  },
  Mutation: {
    createUser: (_, { firstName, lastName, email, password, gender, username }) => {
      if (users.find((user) => user.email === email)) {
        throw new Error('User already exists');
      }

      const newUser = {
        id: users.length + 1,
        firstName,
        lastName,
        email,
        password,
        gender,
        username,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      users.push(newUser);
      saveUsersToFile();
      return { ...newUser, password: null }; // Return user without password
    },
  },
};

// Create the Apollo Server
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true, // Enables introspection for Apollo Studio
    playground: true,    // Enables GraphQL Playground
});

(async () => {
    const { url } = await startStandaloneServer(server, {
        listen: { port: process.env.PORT || 4001 }, // Use the platform's assigned port or default to 4000
        context: async () => ({
            apiKey: process.env.APOLLO_KEY || null, // Optional: Apollo Studio API key
        }),
    });

    console.log(`🚀 Server ready at ${url}`);
})();

