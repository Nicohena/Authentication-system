import jwt from 'jsonwebtoken';

const userauth = async (req, res, next) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ success: false, message: "Unauthorized: No token provided" });
    }
    try {

        const tokendecoded = jwt.verify(token, process.env.JWT_SECRET);
        if (tokendecoded.id) {
            req.body.userid = tokendecoded.id;
        } else {
            return res.status(401).json({ success: false, message: "Unauthorized: Invalid token" });
        }
        next();

    } catch (error) {
        return res.status(401).json({ success: false, message: "Unauthorized: Invalid token" });
    }
}
export default userauth;