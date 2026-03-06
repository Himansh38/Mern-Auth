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

const allowedOrigins = [
    process.env.CLIENT_URL,
    process.env.FRONTEND_URL,
    'http://localhost:5173',
    'https://mern-auth-delta-six.vercel.app',
].filter(Boolean);

const isAllowedOrigin = (origin) => {
    if (!origin) return true; // non-browser requests
    if (allowedOrigins.includes(origin)) return true;
    // Allow Vercel preview/prod domains for this project family.
    if (/^https:\/\/mern-auth-.*\.vercel\.app$/.test(origin)) return true;
    return false;
};

const corsOptions = {
    origin: (origin, callback) => {
        if (isAllowedOrigin(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

//API Endpoints 
app.get('/', (req, res)=> res.send("server is running"))
app.use('/api/auth' , authRouter)
app.use('/api/user' , userRouter)


app.listen(port , ()=> console.log(`server  started on PORT : ${port}`))

