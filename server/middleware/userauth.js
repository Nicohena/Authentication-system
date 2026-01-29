import jwt from 'jsonwebtoken';

const userauth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({ success: false, message: "Unauthorized: No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded.userId) {
            req.user = { id: decoded.userId }; // attach user info
            next();
        } else {
            return res.status(401).json({ success: false, message: "Unauthorized: Invalid token" });
        }

    } catch (error) {
        return res.status(401).json({ success: false, message: "Unauthorized: Invalid token" });
    }
};

export default userauth;
