import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';
import transporter from '../config/nodemailer.js';

// REGISTER CONTROLLER
export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    try {
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ success: false, message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        if (!process.env.JWT_SECRET) {
            return res.status(500).json({ success: false, message: "JWT_SECRET not configured" });
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
            text: `Hello ${name},\n\nThank you for registering at our service!\n\nBest regards,\nThe Team`
        };

        try {
            await transporter.sendMail(mailOptions);
        } catch (err) {
            console.error('Welcome email failed:', err.message);
        }

        return res.status(201).json({ success: true, message: "User registered successfully" });

    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// LOGIN CONTROLLER
export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).json({ success: false, message: "All fields are required" });

    try {
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User does not exist" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: "Invalid credentials" });

        if (!process.env.JWT_SECRET) return res.status(500).json({ success: false, message: 'JWT_SECRET not configured' });

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({ success: true, message: "Login successful" });

    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// LOGOUT CONTROLLER
export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        return res.status(200).json({ success: true, message: "Logout successful" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// SEND VERIFICATION OTP
export const sendVerifyOtp = async (req, res) => {
    try {
        const userId = req.user.id; // from auth middleware
        const user = await userModel.findById(userId);

        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        if (user.isAccountVerified) return res.status(400).json({ success: false, message: "Account already verified" });

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyotp = otp;
        user.verifyotpexpireat = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Hello ${user.name},\n\nYour OTP for account verification is ${otp}. It is valid for 24 hours.\n\nBest regards,\nThe Team`
        };

        try {
            await transporter.sendMail(mailOptions);
        } catch (err) {
            console.error('OTP email failed:', err.message);
            return res.status(500).json({ success: false, message: "Failed to send OTP email" });
        }

        return res.status(200).json({ success: true, message: "Verification OTP sent to your email" });
    } catch (error) {
        console.error('sendVerifyOtp error:', error.message);
        return res.status(500).json({ success: false, message: error.message });
    }
};

// VERIFY EMAIL USING OTP
export const verifyEmail = async (req, res) => {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ success: false, message: "OTP is required" });

    try {
        const userId = req.user.id; // from auth middleware
        const user = await userModel.findById(userId);

        if (!user) return res.status(404).json({ success: false, message: "User not found" });
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

        return res.status(200).json({ success: true, message: "Account verified successfully" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};
//
export const isAuthenticated = async (req, res) => {
try{

    return res.json({ success: true });

}catch (error) {
    return res.status(500).json({ success: false, message: error.message });
}}
