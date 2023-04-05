import prisma from "../../../lib/prisma";
import { authMiddleware } from "../../../lib/middleware";

export default authMiddleware(async function handler(req, res){
    if (req.method === 'GET') {
        const userId = req.user.userId;

        const user = await prisma.user.findUnique({where: {id: userId}});

        if (!user){
            return res.status(401).json({message: 'Invalid token'});
        }

        return res.status(200).json({ user });
    }
    else{
        return res.status(405).json({message: 'method not allowed'});
    }
});