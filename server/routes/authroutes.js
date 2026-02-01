import express from 'express';
import {
    login, register, logout,
    sendVerifyOtp, verifyEmail,
    isAuthenticated, sendResetotp, resetPassword, verifyResetOtp
} from '../controllers/authcontroller.js';
import userauth from '../middleware/userauth.js';

const authRouter = express.Router();

// Public routes
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-reset-otp', sendResetotp);
authRouter.post('/verify-reset-otp', verifyResetOtp);
authRouter.post('/reset-password', resetPassword);

// Protected routes
authRouter.post('/send-verify-otp', userauth, sendVerifyOtp);
authRouter.post('/verify-account', userauth, verifyEmail);
authRouter.get('/is-auth', userauth, isAuthenticated);

export default authRouter;
