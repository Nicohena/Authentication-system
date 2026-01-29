import User from '../models/usermodel.js';

export const getuserdata = async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId).select('-password -verifyotp -resetotp');
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        return res.json({ success: true, user });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};
