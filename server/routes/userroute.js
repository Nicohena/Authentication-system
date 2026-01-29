import express from 'express';
import userauth from '../middleware/userauth.js';
import { getuserdata } from '../controllers/usercontroller.js';

const userRouter = express.Router();

userRouter.get('/data', userauth, getuserdata);

export default userRouter;
