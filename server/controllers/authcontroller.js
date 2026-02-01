import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplate.js';

// REGISTER
export const register = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    try {
        const existingUser = await userModel.findOne({ email });
        if (existingUser) return res.status(409).json({ success: false, message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: false,
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome!',
            text: `Hello ${name},\n\nWelcome to our service!`
        });

        return res.status(201).json({ success: true, message: "User registered successfully" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// LOGIN
export const login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "All fields are required" });

    try {
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User does not exist" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: "Invalid credentials" });

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: false,
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({ success: true, message: "Login successful" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// LOGOUT
export const logout = async (req, res) => {
    try {
        res.clearCookie('token', { httpOnly: true, sameSite: 'lax', secure: false });
        return res.status(200).json({ success: true, message: "Logout successful" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// SEND VERIFICATION OTP
export const sendVerifyOtp = async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await userModel.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        if (user.isAccountVerified) return res.status(400).json({ success: false, message: "Account already verified" });

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyotp = otp;
        user.verifyotpexpireat = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            // text: `Your OTP is: ${otp}`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)

        });

        return res.status(200).json({ success: true, message: "OTP sent successfully" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// VERIFY EMAIL
export const verifyEmail = async (req, res) => {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ success: false, message: "OTP is required" });

    try {
        const userId = req.user.id;
        const user = await userModel.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (user.verifyotp !== otp) return res.status(400).json({ success: false, message: "Invalid OTP" });
        if (user.verifyotpexpireat < Date.now()) return res.status(400).json({ success: false, message: "OTP expired" });

        user.isAccountVerified = true;
        user.verifyotp = '';
        user.verifyotpexpireat = 0;
        await user.save();

        return res.status(200).json({ success: true, message: "Account verified successfully" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// CHECK AUTH

export const isAuthenticated = async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await userModel.findById(decoded.userId).select('-password');
    if (!user) return res.status(401).json({ success: false, message: 'Unauthorized' });

    return res.status(200).json({ success: true, user });
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
};


// SEND RESET PASSWORD OTP
export const sendResetotp = async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "Email is required" });

    try {
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetotp = otp;
        user.resetotpexpireat = Date.now() + 15 * 60 * 1000; // 15 mins
        await user.save();

        await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Your OTP is: ${otp}`,
            html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        });

        return res.json({ success: true, message: "Password reset OTP sent" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// VERIFY RESET OTP
export const verifyResetOtp = async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ success: false, message: "Email and OTP are required" });

    try {
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (user.resetotp !== otp) return res.status(400).json({ success: false, message: "Invalid OTP" });
        if (user.resetotpexpireat < Date.now()) return res.status(400).json({ success: false, message: "OTP expired" });

        return res.json({ success: true, message: "OTP verified successfully" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

// RESET PASSWORD
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) return res.status(400).json({ success: false, message: "All fields required" });

    try {
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (user.resetotp !== otp) return res.status(400).json({ success: false, message: "Invalid OTP" });
        if (user.resetotpexpireat < Date.now()) return res.status(400).json({ success: false, message: "OTP expired" });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetotp = '';
        user.resetotpexpireat = 0;
        await user.save();

        return res.json({ success: true, message: "Password reset successfully" });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};
