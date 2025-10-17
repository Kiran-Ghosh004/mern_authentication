import mongoose from "mongoose";


const connectDB = async () => {
    mongoose.connection.on("connected", () => {
        console.log("Mongoose connected to DB");
    });
    await mongoose.connect(`${process.env.MONGODB_URI}/kiran`);
    console.log("MongoDB connected");
};

export default connectDB;