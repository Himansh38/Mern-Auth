import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRouters.js";
import userRouter from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 4000;

// Connect Database
connectDB();

// Allowed Origins
const allowedOrigins = [
  "http://localhost:5173",
  "https://mern-auth-delta-six.vercel.app"
];

// CORS Middleware
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true
  })
);

// Middlewares
app.use(express.json());
app.use(cookieParser());

// API Endpoints
app.get("/", (req, res) => res.send("Server is running"));

app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

// Start Server
app.listen(port, () => {
  console.log(`Server started on PORT: ${port}`);
});