import express from 'express';
import { login, register, logout,sendverifyotp, verifyEmail } from '../controllers/authcontroller.js';
import userauth from '../middleware/userauth.js';

const authRouter = express.Router();

// Sample route for authentication
authRouter.post('/register', register)
authRouter.post('/login', login)
authRouter.post('/logout', logout)
authRouter.post('/send-verify-otp',userauth, sendverifyotp)
authRouter.post('/verify-account',userauth, verifyEmail)

export default authRouter;



