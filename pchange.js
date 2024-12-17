const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Secrets for JWT
const JWT_SECRET = 'supersecretkey';
const ADMIN_SECRET = 'adminsecretkey';

// Utility functions to read/write files
const loadFromFile = (filename) => {
    if (!fs.existsSync(filename)) {
        console.warn(`${filename} not found, initializing with an empty array.`);
        return [];
    }
    try {
        return JSON.parse(fs.readFileSync(filename, 'utf8'));
    } catch (error) {
        console.error(`Error reading or parsing ${filename}:`, error.message);
        return [];
    }
};

const saveToFile = (filename, data) => {
    fs.writeFileSync(filename, JSON.stringify(data, null, 2));
};

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
      throw new Error('Unauthorized: Invalid or expired user token');
    }
};

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

// Define the GraphQL schema
const typeDefs = gql`
  type Query {
    generateOTP(email: String!): OTPResponse!
  }

  type Mutation {
    changeUserPassword(token: String, otp: String, oldPassword: String, newPassword: String!): String!
    changeAdminPassword(adminToken: String, otp: String, oldPassword: String, newPassword: String!): String!
    changeUserEmail(token: String, otp: String, newEmail: String!): String!
  }

  type OTPResponse {
    otp: String!
    expiry: String!
  }

  type User {
    id: ID!
    username: String!
    email: String!
  }

  type Admin {
    id: ID!
    username: String!
    email: String!
  }
`;

let otpStore = {}; // Temporary store for OTPs

// Generate OTP function
const generateOTP = (email, isAdmin) => {
  const otp = (Math.floor(100000 + Math.random() * 900000)).toString(); // 6-digit OTP
  const expiry = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // Expires in 15 minutes

  const admins = loadFromFile('admins.json');
  const users = loadFromFile('users.json');

  if (isAdmin) {
    const admin = admins.find((a) => a.email === email);
    if (!admin) {
      throw new Error('Admin email not found');
    }
    otpStore[otp] = { expiry, id: admin.id, type: 'admin' };
  } else {
    const user = users.find((u) => u.email === email);
    if (!user) {
      throw new Error('User email not found');
    }
    otpStore[otp] = { expiry, id: user.id, type: 'user' };
  }

  setTimeout(() => delete otpStore[otp], 15 * 60 * 1000); // Automatically remove expired OTP
  return { otp, expiry };
};

// Resolver functions
const resolvers = {
  Query: {
    generateOTP: (_, { email }) => {
      const admins = loadFromFile('admins.json');
      const isAdmin = admins.some((a) => a.email === email);
      return generateOTP(email, isAdmin);
    },
  },

  Mutation: {
    changeUserPassword: (_, { token, otp, oldPassword, newPassword }) => {
      const users = loadFromFile('users.json');
      if (!token && !otp) {
        throw new Error('Either token or OTP must be provided');
      }

      let user;
      if (token) {
        const decoded = validateUserToken(token);
        user = users.find((u) => u.id === decoded.id);
        if (!user) {
          throw new Error('Invalid token or user not found');
        }

        if (oldPassword && user.password !== oldPassword) {
          throw new Error('Old password is incorrect');
        }
      }

      if (otp) {
        const otpData = otpStore[otp];
        if (!otpData || new Date() > new Date(otpData.expiry) || otpData.type !== 'user') {
          throw new Error('Invalid or expired OTP');
        }
        user = users.find((u) => u.id === otpData.id);
        if (!user) {
          throw new Error('Invalid OTP or user not found');
        }

        // Invalidate OTP after use
        delete otpStore[otp];
      }

      if (!user) {
        throw new Error('Unable to locate user');
      }

      user.password = newPassword;
      saveToFile('users.json', users);
      return 'User password changed successfully';
    },

    changeAdminPassword: (_, { adminToken, otp, oldPassword, newPassword }) => {
      const admins = loadFromFile('admins.json');
      if (!adminToken && !otp) {
        throw new Error('Either adminToken or OTP must be provided');
      }

      let admin;
      if (adminToken) {
        const decoded = validateAdminToken(adminToken);
        admin = admins.find((a) => a.id === decoded.id);
        if (!admin) {
          throw new Error('Invalid token or admin not found');
        }

        if (oldPassword && admin.password !== oldPassword) {
          throw new Error('Old password is incorrect');
        }
      }

      if (otp) {
        const otpData = otpStore[otp];
        if (!otpData || new Date() > new Date(otpData.expiry) || otpData.type !== 'admin') {
          throw new Error('Invalid or expired OTP');
        }
        admin = admins.find((a) => a.id === otpData.id);
        if (!admin) {
          throw new Error('Invalid OTP or admin not found');
        }

        // Invalidate OTP after use
        delete otpStore[otp];
      }

      if (!admin) {
        throw new Error('Unable to locate admin');
      }

      admin.password = newPassword;
      saveToFile('admins.json', admins);
      return 'Admin password changed successfully';
    },

    changeUserEmail: (_, { token, otp, newEmail }) => {
      const users = loadFromFile('users.json');
      if (!token || !otp) {
        throw new Error('Both token and OTP must be provided');
      }

      const decoded = validateUserToken(token);
      const user = users.find((u) => u.id === decoded.id);
      if (!user) {
        throw new Error('Invalid token or user not found');
      }

      const otpData = otpStore[otp];
      if (!otpData || new Date() > new Date(otpData.expiry) || otpData.type !== 'user' || otpData.id !== user.id) {
        throw new Error('Invalid or expired OTP');
      }

      if (!newEmail || !newEmail.includes('@')) {
        throw new Error('A valid email address must be provided');
      }

      user.email = newEmail;
      saveToFile('users.json', users);

      // Invalidate OTP after use
      delete otpStore[otp];

      return 'User email changed successfully';
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
