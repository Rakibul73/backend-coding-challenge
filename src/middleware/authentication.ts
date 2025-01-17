import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import redisClient from "../utils/redisClient";
import { ERROR_MESSAGES } from "../constants/messages";

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!;

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
    return;
  }

  const token = authHeader.split(" ")[1];

  try {
    // Check if the token is blacklisted
    const isBlacklisted = await redisClient.get(`blacklist:${token}`);
    if (isBlacklisted) {
      res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
      return;
    }

    // Verify the token
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET) as { id: string };

    // Attach user ID to the request
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
    return;
  }
};
