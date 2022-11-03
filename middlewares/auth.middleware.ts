import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import Error from "../interfaces/error.interface";
import User from "../models/user.model";

const handleUnauthorizedError = (
  next: NextFunction,
  message?: string,
  status?: number
) => {
  const error: Error = new Error(message || "Please authenticate");
  error.status = status || 401;
  next(error);
};

const validationMiddleware = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.get("authorization");

    if (authHeader) {
      const bearer = authHeader.split(" ")[0];
      const token = authHeader.split(" ")[1];

      if (!token || bearer !== "Bearer") {
        handleUnauthorizedError(next);
      } else {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string);

        const id = (decoded as JwtPayload).id;

        const user = await User.findById(id);

        if (decoded && user) {
          next();
        } else {
          handleUnauthorizedError(next);
        }
      }
    } else {
      handleUnauthorizedError(next);
    }
  } catch (error) {
    next(error);
  }
};

export default validationMiddleware;
