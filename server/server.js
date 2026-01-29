import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authroutes.js';
import userRouter from './routes/userroute.js';

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors({ credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

// Start the server

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
