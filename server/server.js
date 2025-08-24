import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/authRoutes.js';
import { errorHandler } from './middleware/errorHandler.js';


dotenv.config();
const app=express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("API is running 🚀");
});


// Routes
app.use("/api/auth", authRoutes);

app.use(errorHandler)

mongoose.connect(process.env.MONGO_URI,{
    useNewUrlParser:true,useUnifiedTopology:true
})
.then(()=>{
    console.log("MongoDB Connected");
    app.listen(5000,()=>console.log("Server running on port 5000"))
})
.catch(err=>console.log(err))


console.log("Server is running...")