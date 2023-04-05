import { verify, sign } from "jsonwebtoken";

const JWT_SECRET = 'belajar-jwt-itu-mudah-dan-menyenangkan';

export function authMiddleware(handler) {
    return async (req, res) => {
        const authorizationHeader = req.headers['authorization'];

        if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message : "Authorization header invalid" });
        }

        const token = authorizationHeader.split(' ')[1];

        try {
            const decoded = verify(token, JWT_SECRET);

            const now = Math.floor(Date.now() / 1000);

            const expiresAt = decoded.exp;

            if (expiresAt - now < 60 * 30) {
                const newToken = sign({ ...decoded, exp: now + 60 * 60 }, JWT_SECRET);
                res.setHeader('Authorization', `Bearer ${newToken}`);
            }

            req.user = decoded;
            return handler(req, res);
        }
        catch(error) {
            return res.status(401).json({ message: "Invalid token" });
        }
    }
}
