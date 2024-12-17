const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Secret for JWT
const JWT_SECRET = 'supersecretkey';
const ADMIN_SECRET = 'adminsecretkey';

// Utility Functions
const loadFromFile = (filename) => {
  if (fs.existsSync(filename)) {
    return JSON.parse(fs.readFileSync(filename));
  }
  return [];
};

const saveToFile = (filename, data) => {
  fs.writeFileSync(filename, JSON.stringify(data, null, 2));
};

const validateUserToken = (token) => {
  try {
    console.log('Validating user token:', token);

    // Fetch the latest user tokens
    const userTokens = loadFromFile('tokens.json');

    // Trim token to remove unnecessary whitespace
    token = token.trim();

    // Check if the token exists in the latest user tokens
    if (!userTokens.includes(token)) {
      console.error('Token not found in tokens.json:', token);
      throw new Error('Unauthorized: Invalid user token');
    }

    // Decode and verify the token
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded; // Return the decoded payload
  } catch (err) {
    console.error('User token validation error:', err.message);
    throw new Error('Unauthorized: Invalid or expired user token');
  }
};

const generateId = (prefix = 'Order') => {
  // Generate a random string and encode it in base64
  const randomString = crypto.randomBytes(16).toString('hex');
  const base64String = Buffer.from(randomString).toString('base64');
  
  // Combine the base64 string and prefix
  return `${base64String}`;
};

const validateAdminToken = (adminToken) => {
  try {
    console.log('Validating admin token:', adminToken);

    // Fetch the latest admin tokens
    const adminTokens = loadFromFile('adtokens.json');

    // Trim the token to avoid formatting issues
    adminToken = adminToken.trim();

    // Check if the token exists in the latest admin tokens
    if (!adminTokens.includes(adminToken)) {
      console.error('Admin token not found in adtokens.json:', adminToken);
      throw new Error('Unauthorized: Invalid admin token');
    }

    // Decode and verify the admin token
    const decoded = jwt.verify(adminToken, ADMIN_SECRET);
    return decoded; // Return the decoded payload
  } catch (err) {
    console.error('Admin token validation error:', err.message);
    throw new Error('Unauthorized: Invalid or expired admin token');
  }
};

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

// Resolver functions
const resolvers = {
  Query: {
    login: (_, { email, password }) => {
      const users = loadFromFile('users.json'); // Load users dynamically
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
    
      const userTokens = loadFromFile('tokens.json'); // Always load the latest tokens
      userTokens.push(token);
      saveToFile('tokens.json', userTokens); // Save updated tokens
    
      return { token, user: { ...user, password: null } };
    },       
    adminLogin: (_, { email, password }) => {
      const admins = loadFromFile('admins.json'); // Load admins dynamically
      const admin = admins.find((admin) => admin.email === email);
    
      if (!admin) {
        throw new Error('Admin not found');
      }
    
      if (admin.password !== password) {
        throw new Error('Invalid password');
      }
    
      const adminToken = jwt.sign(
        { id: admin.id, email: admin.email, admin: true },
        ADMIN_SECRET,
        { expiresIn: '1h' }
      );
    
      const adminTokens = loadFromFile('adtokens.json'); // Always load the latest tokens
      adminTokens.push(adminToken);
      saveToFile('adtokens.json', adminTokens); // Save updated admin tokens
    
      // Ensure the resolver returns both the adminToken and the admin object
      return {
        adminToken,
        admin, // Return the valid admin object
      };
    },    
    getAllUsers: (_, { adminToken }) => {
      validateAdminToken(adminToken); // Dynamically validate admin token
      const users = loadFromFile('users.json'); // Load users dynamically
      return users.map((user) => ({ ...user, password: null })); // Return users without passwords
    },    
    getDeletedUsers: (_, { adminToken }) => {
      validateAdminToken(adminToken); // Validate admin token
      return loadFromFile('spam.json'); // Load deleted users dynamically
    },

    getTokens: (_, { adminToken }) => {
      validateAdminToken(adminToken); // Validate admin token
      return loadFromFile('tokens.json'); // Return all user tokens
    },
  },
  Mutation: {
    createUser: (_, { firstName, lastName, email, password, gender, username }) => {
      const users = loadFromFile('users.json'); // Load users dynamically
    
      // Check if the user already exists
      if (users.find((user) => user.email === email)) {
        throw new Error('User already exists');
      }
    
      // Generate the unique user ID
      const userId = generateId(); // Use "User" as the suffix
    
      // Create a new user
      const newUser = {
        id: userId,
        firstName,
        lastName,
        email,
        password,
        gender,
        username,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
    
      // Add the new user to the database
      users.push(newUser);
      saveToFile('users.json', users); // Save the updated users list to the file
    
      // Return the new user (without the password)
      return { ...newUser, password: null };
    },        
    createAdmin: (_, { firstName, lastName, email, password, username }) => {
      const admins = loadFromFile('admins.json'); // Load admins dynamically
    
      // Check if the admin already exists
      if (admins.find((admin) => admin.email === email)) {
        throw new Error('Admin already exists');
      }
    
      // Generate the unique admin ID
      const adminId = generateId(); // Use "Admin" as the suffix
    
      // Create a new admin
      const newAdmin = {
        id: adminId,
        firstName,
        lastName,
        email,
        username,
        password, // Consider hashing this in production
        createdAt: new Date().toISOString(),
      };
    
      // Add the new admin to the database
      admins.push(newAdmin);
      saveToFile('admins.json', admins); // Save the updated admins list to the file
    
      // Return the new admin (without the password)
      return { ...newAdmin, password: null };
    },       
    deleteUser: (_, { adminToken, userId }) => {
      validateAdminToken(adminToken); // Validate admin token
      const users = loadFromFile('users.json'); // Load users dynamically
      const deletedUsers = loadFromFile('spam.json'); // Load deleted users dynamically

      const userIndex = users.findIndex((user) => user.id === userId);
      if (userIndex === -1) {
        throw new Error('User not found');
      }

      const [removedUser] = users.splice(userIndex, 1);
      deletedUsers.push(removedUser);

      saveToFile('users.json', users); // Save updated users
      saveToFile('spam.json', deletedUsers); // Save updated deleted users

      return `User with ID ${userId} has been deleted.`;
    },

    logout: (_, { token }) => {
      const userTokens = loadFromFile('tokens.json'); // Fetch the latest user tokens
      const adminTokens = loadFromFile('adtokens.json'); // Fetch the latest admin tokens
    
      if (userTokens.includes(token)) {
        const updatedUserTokens = userTokens.filter((t) => t !== token);
        saveToFile('tokens.json', updatedUserTokens); // Save updated user tokens
        return 'Successfully logged out';
      }
    
      if (adminTokens.includes(token)) {
        const updatedAdminTokens = adminTokens.filter((t) => t !== token);
        saveToFile('adtokens.json', updatedAdminTokens); // Save updated admin tokens
        return 'Successfully logged out';
      }
    
      throw new Error('Invalid or expired token');
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
