import express from 'express';
import { login, register, logout } from '../controllers/authcontroller.js';

const authRouter = express.Router();

// Sample route for authentication
authRouter.post('/register', register)
authRouter.post('/login', login)
authRouter.post('/logout', logout)

export default authRouter;



