import dotenv from "dotenv";
dotenv.config();

import cookieParser from "cookie-parser";
import cors from "cors";
import express, { Application, Request, Response } from "express";
import helmet from "helmet";
import corsOption from "./config/corsOption";
import limiter from "./config/limiter";
import { connectDB } from "./db/connect";
import errorMiddleware from "./middlewares/error.middleware";
import userRouter from "./routes/user.route";

export const app: Application = express();
app.use(express.json());
app.use(helmet());
app.use(cookieParser());
app.use(cors(corsOption));
app.options("*", cors());
app.use(limiter);

connectDB(process.env.MONGODB_CONNECTION_URL as string);

app.get("/", (_: Request, res: Response) => {
  res.send("<h1>Stock API Working 🚀🚀</h1>");
});

app.use("/users", userRouter);

app.use(errorMiddleware);

app.use((_: Request, res: Response) => {
  res.status(404).json({
    message:
      "Ohh you are lost, read the API documentation to find your way back home 😂",
  });
});
