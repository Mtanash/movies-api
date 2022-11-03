import dotenv from "dotenv";
dotenv.config();

import bcrypt from "bcrypt";
import { NextFunction, Request, Response } from "express";
import mongoose from "mongoose";
import User from "../models/user.model";

export const createNewUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { password, email } = req.body;

    // make sure the email is not already in the database
    const emailExist = await User.findOne({ email });
    if (emailExist) throw new Error("Please provide a valid email address");

    const hashedPassword = await bcrypt.hash(
      password,
      parseInt(process.env.SALT_ROUNDS as string)
    );

    const user = new User({
      ...req.body,
      password: hashedPassword,
    });

    await user.save();

    const accessToken = User.generateAccessToken(user._id);

    res.status(201).json({
      message: "User created successfully",
      data: {
        user: { name: user.name, _id: user._id, email: user.email },
        accessToken,
      },
    });
  } catch (error) {
    next(error);
  }
};

export const getUserById = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const userId = req.params.userId;

    if (!mongoose.Types.ObjectId.isValid(userId))
      throw new Error(`Invalid user ID`);

    const user = await User.findById(userId);

    if (!user) throw new Error("User not found");

    res
      .status(200)
      .json({ data: { name: user.name, _id: user._id, email: user.email } });
  } catch (error) {
    next(error);
  }
};

export const deleteUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const userId = req.params.userId;

    if (!mongoose.Types.ObjectId.isValid(userId))
      throw new Error(`Invalid user ID`);

    if (!(await User.findById(userId))) throw new Error(`User not found`);

    await User.findByIdAndDelete(userId);

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    next(error);
  }
};

export const loginUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password } = req.body;

    const user = await User.authenticate(email, password);

    if (!user) throw new Error("User not found");

    const accessToken = User.generateAccessToken(user._id);

    res.status(200).json({
      message: "User Logged in successfully",
      data: {
        user: { name: user.name, _id: user._id, email: user.email },
        accessToken,
      },
    });
  } catch (error) {
    next(error);
  }
};
