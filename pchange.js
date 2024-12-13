const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { gql } = require('graphql-tag');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Secrets for JWT
const JWT_SECRET = 'supersecretkey';
const ADMIN_SECRET = 'adminsecretkey';

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

// Mock databases
const users = JSON.parse(fs.readFileSync('users.json', 'utf8')) || [];
const admins = JSON.parse(fs.readFileSync('admins.json', 'utf8')) || [];

let otpStore = {}; // Temporary store for OTPs

const saveUsersToFile = () => {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
};

const saveAdminsToFile = () => {
  fs.writeFileSync('admins.json', JSON.stringify(admins, null, 2));
};

// Generate OTP function
const generateOTP = (email, isAdmin) => {
  const otp = (Math.floor(100000 + Math.random() * 900000)).toString(); // 6-digit OTP
  const expiry = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // Expires in 15 minutes

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
      const isAdmin = admins.some((a) => a.email === email);
      return generateOTP(email, isAdmin);
    },
  },

  Mutation: {
    changeUserPassword: (_, { token, otp, oldPassword, newPassword }) => {
      if (!token && !otp) {
        throw new Error('Either token or OTP must be provided');
      }

      let user;
      if (token) {
        const decoded = jwt.verify(token, JWT_SECRET);
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
      saveUsersToFile();
      return 'User password changed successfully';
    },

    changeAdminPassword: (_, { adminToken, otp, oldPassword, newPassword }) => {
      if (!adminToken && !otp) {
        throw new Error('Either adminToken or OTP must be provided');
      }

      let admin;
      if (adminToken) {
        const decoded = jwt.verify(adminToken, ADMIN_SECRET);
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
      saveAdminsToFile();
      return 'Admin password changed successfully';
    },

    changeUserEmail: (_, { token, otp, newEmail }) => {
      if (!token || !otp) {
        throw new Error('Both token and OTP must be provided');
      }

      const decoded = jwt.verify(token, JWT_SECRET);
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
      saveUsersToFile();

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
