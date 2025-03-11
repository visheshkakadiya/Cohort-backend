import mongoose from "mongoose";
import {DB_name} from "../constants.js"
import dotenv from "dotenv"

dotenv.config()
const connectDB = async () => {

    try {
        await mongoose.connect(`${process.env.MONGO_URI}/${DB_name}`)
        console.log(`Mongo DB Connected SuccessFully !!`)
    } catch (error) {
        console.log(`Failed to connect with Mongo DB: ${error}`)
        process.exit(1)
    }
}

export default connectDB