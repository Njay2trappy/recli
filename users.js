const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const jwt = require('jsonwebtoken');

// Define the GraphQL schema
const typeDefs = gql`
  type Query {
    login(email: String!, password: String!): AuthPayload!
    adminLogin(email: String!, password: String!): AdminAuthPayload!
    getAllUsers(adminToken: String!): [User!]!
    getDeletedUsers(adminToken: String!): [User!]!
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
    deleteUser(adminToken: String!, userId: ID!): String!
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
`;

// Mock database
const users = [];
const admins = []
const saveAdminsToFile = () => {
    fs.writeFileSync('admins.json', JSON.stringify(admins, null, 2));
  };
  
  const loadAdminsFromFile = () => {
    if (fs.existsSync('admins.json')) {
      return JSON.parse(fs.readFileSync('admins.json'));
    }
    return [];
  };
  
  // Load admins on start
  Object.assign(admins, loadAdminsFromFile());
  
const deletedUsers = [];
const saveUsersToFile = () => {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
};
const saveDeletedUsersToFile = () => {
  fs.writeFileSync('spam.json', JSON.stringify(deletedUsers, null, 2));
};
const loadUsersFromFile = () => {
  if (fs.existsSync('users.json')) {
    return JSON.parse(fs.readFileSync('users.json'));
  }
  return [];
};
const loadDeletedUsersFromFile = () => {
  if (fs.existsSync('spam.json')) {
    return JSON.parse(fs.readFileSync('spam.json'));
  }
  return [];
};

// Load users and deleted users on start
Object.assign(users, loadUsersFromFile());
Object.assign(deletedUsers, loadDeletedUsersFromFile());

// Secret for JWT
const JWT_SECRET = 'supersecretkey';
const ADMIN_SECRET = 'adminsecretkey';

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

      return { token, user: { ...user, password: null } }; // Omit password from response
    },
    adminLogin: (_, { email, password }) => {
      const admin = admins.find((admin) => admin.email === email);
      if (!admin) {
        throw new Error('Admin not found');
      }

      if (admin.password !== password) {
        throw new Error('Invalid password');
      }

      const adminToken = jwt.sign({ id: admin.id, email: admin.email }, ADMIN_SECRET, {
        expiresIn: '10m',
      });

      return { adminToken, admin };
    },
    getAllUsers: (_, { adminToken }) => {
      const admin = jwt.verify(adminToken, ADMIN_SECRET);
      if (!admin) {
        throw new Error('Invalid admin token');
      }
      return users.map((user) => ({ ...user, password: null }));
    },
    getDeletedUsers: (_, { adminToken }) => {
      const admin = jwt.verify(adminToken, ADMIN_SECRET);
      if (!admin) {
        throw new Error('Invalid admin token');
      }
      return deletedUsers;
    },
  },
  Mutation: {
    createUser: (_, { firstName, lastName, email, password, gender, username }) => {
      if (users.find((user) => user.email === email)) {
        throw new Error('User already exists');
      }

      const newUser = {
        id: (users.length + 1).toString(), // Ensure id is a string
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
    createAdmin: async (_, { firstName, lastName, email, password, username }) => {
        if (admins.find((admin) => admin.email === email)) {
          throw new Error('Admin already exists');
        }
      
        const newAdmin = {
          id: (admins.length + 1).toString(),
          firstName,
          lastName,
          email,
          username,
          password, // Store as plaintext or hashed for security
          createdAt: new Date().toISOString(),
        };
      
        admins.push(newAdmin);
        saveAdminsToFile(); // Save admin details to the file
      
        return newAdmin;
      },      
    deleteUser: (_, { adminToken, userId }) => {
        const admin = jwt.verify(adminToken, ADMIN_SECRET);
        if (!admin) {
          throw new Error('Invalid admin token');
        }
      
        const usersFromFile = loadUsersFromFile(); // Dynamically load the users from the file
        const userIndex = usersFromFile.findIndex((user) => user.id === userId);
      
        if (userIndex === -1) {
          throw new Error('User not found');
        }
      
        const [removedUser] = usersFromFile.splice(userIndex, 1); // Remove the user
        deletedUsers.push(removedUser);
      
        // Save updated users and deleted users to their respective files
        fs.writeFileSync('users.json', JSON.stringify(usersFromFile, null, 2));
        saveDeletedUsersToFile();
      
        return `User with ID ${userId} has been deleted.`;
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
