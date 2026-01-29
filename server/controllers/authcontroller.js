import bycrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';
import transporter from '../config/nodemailer.js';
//register controller
export const register = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.json({ success: false, message: "All fields are required" });
    }
    try {
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ success: false, message: "User already exists" });
        }
        const hashedPassword = await bycrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();


        if (!process.env.JWT_SECRET) {
            return res.status(500).json({ success: false, message: 'JWT_SECRET not configured' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        // Send welcome email

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Our Service',
            text: `Hello ${name},\n\nThank you for registering at our service!\n\nBest regards,\nThe Team you are registered with ${email}`
        }
        await transporter.sendMail(mailOptions);
        return res.json({ success: true, message: "User registered successfully" });


    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}
//login controller
export const login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.json({ success: false, message: "All fields are required" });
    }
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: "User does not exist" });
        }
        const isMatch = await bycrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }
        if (!process.env.JWT_SECRET) {
            return res.status(500).json({ success: false, message: 'JWT_SECRET not configured' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        return res.json({ success: true, message: "Login successful" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}
//logout controller
export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });
        return res.json({ success: true, message: "Logout successful" });

    }
    catch (error) {
        return res.json({ success: false, message: error.message });
    }
}
// Send verification OTP
export const sendverifyotp = async (req, res) => {
    try {
        const { userid } = req.body;
        const user = await userModel.findById(userid);
        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Account already verified" });
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyotp = otp;
        user.verifyotpexpireat = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Hello ${user.name},\n\nYour OTP for account verification is ${otp}. It is valid for 24 hours.\n\nBest regards,\nThe Team`
        };
        await transporter.sendMail(mailOptions);
        return res.json({
            success: true, message: "Verification OTP sent to your email"
        })
    }
    catch (error) {
        res.json({ success: false, message: error.message });
    }
}
// Verify account using OTP
export const verifyEmail = async (req, res) => {
    const { userid, otp } = req.body;
    if (!userid || !otp) {
        return res.json({ success: false, message: "All fields are required" });
    }
    try {
        const user = await userModel.findById(userid);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }
        if (user.verifyotp === '' || user.verifyotp !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        }
        if (user.verifyotpexpireat < Date.now()) {
            return res.status(400).json({ success: false, message: "OTP has expired" });

        }
        user.isAccountVerified = true;
        user.verifyotp = '';
        user.verifyotpexpireat = 0;
        await user.save();
        return res.json({ success: true, message: "Account verified successfully" });
    }
    catch (error) {
        return res.json({ success: false, message: error.message });
    }
}