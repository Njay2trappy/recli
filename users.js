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
    getAllUsers(adminToken: String): [User!]!
    getDeletedUsers(adminToken: String): [User!]!
    getTokens(adminToken: String!): [String!]!
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
const admins = [];
const activeTokens = new Set();
const tokensFile = 'tokens.json';

const saveTokensToFile = () => {
  const userTokens = [...activeTokens].filter((token) => {
    const decoded = jwt.decode(token);
    return decoded && !decoded.admin; // Filter user tokens
  });

  const adminTokens = [...activeTokens].filter((token) => {
    const decoded = jwt.decode(token);
    return decoded && decoded.admin; // Filter admin tokens
  });

// Save user tokens
  fs.writeFileSync(tokensFile, JSON.stringify(userTokens, null, 2));

// Save admin tokens
  fs.writeFileSync('adtokens.json', JSON.stringify(adminTokens, null, 2));
};

  

const loadTokensFromFile = () => {
  if (fs.existsSync(tokensFile)) {
    return new Set(JSON.parse(fs.readFileSync(tokensFile)));
  }
  return new Set();
};

const loadAdminTokensFromFile = () => {
  if (fs.existsSync('adtokens.json')) {
    return new Set(JSON.parse(fs.readFileSync('adtokens.json')));
  }
  return new Set();
};

// On server start, load tokens
activeTokens.add(...loadTokensFromFile());
activeTokens.add(...loadAdminTokensFromFile());


const revokeToken = (token) => {
  activeTokens.delete(token);
  saveTokensToFile();
};

// Helper function to validate token
const validateToken = (token, secret) => {
  if (!activeTokens.has(token)) {
    throw new Error('Token is invalid or has expired');
  }

  try {
    return jwt.verify(token, secret);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      activeTokens.delete(token);
      saveTokensToFile();
      if (secret === ADMIN_SECRET) {
        fs.writeFileSync('adtokens.json', JSON.stringify([...activeTokens], null, 2));
      }
      throw new Error('Token has expired');
    }
    throw new Error('Token is invalid');
  }
};


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

      const existingToken = [...activeTokens].find((token) => {
        try {
          const decoded = jwt.decode(token);
          return decoded?.email === email;
        } catch {
          return false;
        }
      });
      

      if (existingToken) {
        throw new Error('User is already logged in');
      }

      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: '1h',
      });

      activeTokens.add(token);
      saveTokensToFile();

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
    
      const adminToken = jwt.sign(
        { id: admin.id, email: admin.email, admin: true }, // Add admin flag
        ADMIN_SECRET,
        { expiresIn: '1h' }
      );
    
      activeTokens.add(adminToken);
    
      // Save to adtokens.json
      const adminTokens = [...activeTokens].filter((token) => {
        const decoded = jwt.decode(token);
        return decoded && decoded.admin;
      });
      fs.writeFileSync('adtokens.json', JSON.stringify(adminTokens, null, 2));
    
      return { adminToken, admin };
    },
    getAllUsers: (_, { adminToken }, context) => {
      const token = adminToken || context.token;
      if (!token) {
        throw new Error('Admin token is required');
      }
    
      // Load admin tokens from the database
      const adminTokens = new Set(JSON.parse(fs.readFileSync('adtokens.json')));
    
      // Check if the token is valid
      if (!adminTokens.has(token)) {
        throw new Error('Invalid or expired admin token');
      }
    
      const admin = validateToken(token, ADMIN_SECRET); // Validate the admin token
      return users.map((user) => ({ ...user, password: null }));
    },
    
    getDeletedUsers: (_, { adminToken }, context) => {
      const token = adminToken || context.token;
      if (!token) {
        throw new Error('Admin token is required');
      }
    
      // Load admin tokens from the database
      const adminTokens = new Set(JSON.parse(fs.readFileSync('adtokens.json')));
    
      // Check if the token is valid
      if (!adminTokens.has(token)) {
        throw new Error('Invalid or expired admin token');
      }
    
      const admin = validateToken(token, ADMIN_SECRET); // Validate the admin token
      return deletedUsers;
    },
    getTokens: (_, { adminToken }) => {
      // Validate the admin token
      validateToken(adminToken, ADMIN_SECRET);
    
      // Load all user tokens from tokens.json
      const userTokens = JSON.parse(fs.readFileSync('tokens.json'));
    
      if (!Array.isArray(userTokens)) {
        throw new Error('Invalid token storage format');
      }
    
      // Return the list of user tokens
      return userTokens;
    },
    
  },
  Mutation: {
    createUser: (_, { firstName, lastName, email, password, gender, username }) => {
      if (users.find((user) => user.email === email)) {
        throw new Error('User already exists');
      }

      const newUser = {
        id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,        firstName,
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
        id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,        firstName,
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
    deleteUser: (_, { adminToken, userId }, context) => {
      const token = adminToken || context.token;
      if (!token) {
        throw new Error('Admin token is required');
      }

      const admin = validateToken(token, ADMIN_SECRET);
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
    logout: (_, { token }) => {
        // Load tokens from the appropriate file
        const userTokens = new Set(JSON.parse(fs.readFileSync('tokens.json')));
        const adminTokens = new Set(JSON.parse(fs.readFileSync('adtokens.json')));
      
        // Check if the token is valid in either users or admins
        if (!userTokens.has(token) && !adminTokens.has(token)) {
          throw new Error('Invalid or expired token');
        }
      
        // Remove the token from the respective set
        if (userTokens.has(token)) {
          userTokens.delete(token);
          fs.writeFileSync('tokens.json', JSON.stringify([...userTokens], null, 2));
        } else if (adminTokens.has(token)) {
          adminTokens.delete(token);
          fs.writeFileSync('adtokens.json', JSON.stringify([...adminTokens], null, 2));
        }
      
        return 'Successfully logged out';
      },
      
    
  },
};

// Create the Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Enables introspection for Apollo Studio
  context: ({ req }) => {
    const token = req.headers.authorization || null;
    return { token };
  },
});

(async () => {
  const { url } = await startStandaloneServer(server, {
    listen: { port: process.env.PORT || 4002 }, // Use the platform's assigned port or default to 4001
  });

  console.log(`\uD83D\uDE80 Server ready at ${url}`);
})();
