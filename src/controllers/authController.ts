import bcrypt from "bcrypt";
import { Request, Response } from "express";

import User from "../models/User";
import { SUCCESS_MESSAGES, ERROR_MESSAGES } from "../constants/messages";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
} from "../utils/jwt";
import redisClient from "../utils/redisClient";

export const signup = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).json({ message: SUCCESS_MESSAGES.USER_CREATED });
  } catch (err: Error | any) {
    if (err.code === 11000) {
      res.status(400).json({ error: ERROR_MESSAGES.SIGNUP_FAILED });
    } else {
      res.status(500).json({ error: ERROR_MESSAGES.INTERNAL_SERVER_ERROR });
    }
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      res.status(401).json({ error: ERROR_MESSAGES.INVALID_CREDENTIALS });
      return;
    }

    const accessToken = generateAccessToken(user._id.toString());
    const refreshToken = generateRefreshToken(user._id.toString());

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res
      .status(200)
      .json({ message: SUCCESS_MESSAGES.LOGIN_SUCCESSFUL, accessToken });
  } catch (error) {
    res.status(500).json({ error: ERROR_MESSAGES.INTERNAL_SERVER_ERROR });
  }
};

export const logout = async (req: Request, res: Response): Promise<void> => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
    return;
  }

  const token = authHeader.split(" ")[1];

  try {
    // Decode the token to extract the user ID
    const decoded = verifyToken(token, process.env.ACCESS_TOKEN_SECRET!) as {
      id: string;
      timestamp: number;
    };

    // Calculate remaining time to live for the token
    const expiryTime = Math.floor(decoded.timestamp / 1000) + 30 * 60; // 30 minutes in seconds
    const currentTime = Math.floor(Date.now() / 1000);
    const timeToLive = expiryTime - currentTime;

    // Add the token to the Redis blacklist if it still has time to live
    if (timeToLive > 0) {
      await redisClient.setEx(`blacklist:${token}`, timeToLive, "true");
    }

    // Return the correct status code for a successful logout
    res.sendStatus(204);
  } catch (err) {
    res.status(400).json({ error: ERROR_MESSAGES.INVALID_TOKEN });
  }
};
