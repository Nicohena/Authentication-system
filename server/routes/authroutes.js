import express from 'express';
import { login, register, logout, sendVerifyOtp, verifyEmail } from '../controllers/authcontroller.js';
import userauth from '../middleware/userauth.js';

const authRouter = express.Router();

// Public routes
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);

// Protected routes (require auth)
authRouter.post('/send-verify-otp', userauth, sendVerifyOtp);
authRouter.post('/verify-account', userauth, verifyEmail);

export default authRouter;
