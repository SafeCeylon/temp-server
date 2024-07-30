// src/server.js

import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Middleware
// app.use(
//   cors({
//     origin: 'http://localhost:3000',
//     credentials: true,
//   }),
// );
app.use(express.json());

const PORT = process.env.PORT || 4000;

// User Signup
app.post('/signup', async (req, res) => {
  const { name:name, email, password, nic, mobileNumber} = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const oldUser = await prisma.user.findUnique({ where: { email } });

    if (oldUser) {
      return res.send({status: 400, message: 'User already exists'});
    } else {
      try {
        const newUser = await prisma.user.create({
          data: {
            name,
            email,
            password: hashedPassword,
            nic,
            mobileNumber
          },
        });
        res.send({status: 200, message: 'User created successfully'});
      } catch (error) {
        console.error(error);
        res.send({status: 500, message: 'Internal server error'});
      }
    } 
  } catch (error) {
    console.error(error);
    res.send({status: 500, message: 'Internal server error'});
  }
});

// User Login
app.post('/login', async (req, res) => {
  console.log(req.body);
  const { email, password } = req.body;
  const oldUser = await prisma.user.findUnique({ where: { email } });

  if (!oldUser) {
    return res.send({status: 404, message: 'User does not exist'});
  }

  if (await bcrypt.compare(password, oldUser.password)) {
    const token = jwt.sign({ userId: oldUser.id }, JWT_SECRET, {
      expiresIn: '1h',
    });

    return res.send({status: 200, message: 'User logged in successfully', token});
  } else {
    return res.send({status: 405, message: 'Invalid credentials'});
  }
});

app.post('/userdata', async (req, res) => {
  const {token} = req.body;
  try {
    const user = jwt.verify(token, JWT_SECRET);
    const userId = user.userId;

    const userData = await prisma.user.findUnique({ where: { id: userId } });
    res.send({status: 200, message: 'User data fetched successfully', data: userData});
  } catch (error) {
    console.error(error);
    res.send({status: 500, message: 'Internal server error'});
  }
});

// Verify Token Middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    req.userId = decoded.userId;
    next();
  });
};

// Protected Route Example
app.get('/protected', verifyToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      include: { accounts: true },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
