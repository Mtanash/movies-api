import express from "express";
import validationMiddleware from "../middlewares/auth.middleware";
import {
  createNewUser,
  deleteUser,
  getUserById,
  loginUser,
} from "./../controllers/user.controller";

const userRouter = express.Router();

export default userRouter;

userRouter.post("/", createNewUser);
userRouter.get("/:userId", getUserById);
userRouter.delete("/:userId", validationMiddleware, deleteUser);
userRouter.post("/login", loginUser);
