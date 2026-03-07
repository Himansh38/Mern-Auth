import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRouters.js"
import userRouter from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 4000;
connectDB();

// Allowed Origins
const allowedOrigins = [
  "http://localhost:5173",
  "https://mern-auth-delta-six.vercel.app"
];

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

app.use(express.json()); 
app.use(cookieParser()); 

//API Endpoints 
app.get('/', (req, res)=> res.send("server is running"))
app.use('/api/auth' , authRouter)
app.use('/api/user' , userRouter)


app.listen(port , ()=> console.log(`server  started on PORT : ${port}`))

