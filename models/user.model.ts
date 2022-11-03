import dotenv from "dotenv";
dotenv.config();

import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { model, Model, Schema } from "mongoose";

interface IUser {
  _id: string;
  name: string;
  email: string;
  password: string;
  avatar?: string;
}

interface UserModel extends Model<IUser> {
  authenticate: (name: string, password: string) => Promise<IUser | null>;
  generateAccessToken: (id: string) => string;
}

const userSchema = new Schema<IUser, UserModel>({
  name: {
    type: String,
    required: [true, "Please provide a first name"],
    trim: true,
    min: [3, "Please provide a name with at least 3 characters"],
  },
  email: {
    type: String,
    required: [true, "Please provide a valid email"],
    trim: true,
    lowercase: true,
    unique: true,
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
  },
  avatar: {
    type: String,
  },
});

userSchema.static(
  "authenticate",
  async function authenticate(email: string, password: string) {
    try {
      const User: UserModel = this;
      const user = await User.findOne({ email });

      if (!user) throw new Error("User not found");

      const passwordMatched = bcrypt.compareSync(password, user.password);
      if (!passwordMatched) throw new Error("Failed to authenticate user");

      return user;
    } catch (error) {
      throw new Error(
        `Unable to Login: ${(error as { message: string }).message as string}`
      );
    }
  }
);

userSchema.static("generateAccessToken", function generateAccessToken(id) {
  try {
    return jwt.sign({ id }, process.env.JWT_SECRET as string, {
      expiresIn: "1h",
    });
  } catch (error) {
    throw new Error(
      `Something went wrong. ${(error as { message: string }).message}`
    );
  }
});

const User = model<IUser, UserModel>("user", userSchema);

export default User;
