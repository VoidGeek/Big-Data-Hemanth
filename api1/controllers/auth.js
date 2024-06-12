import User from "../models/User.js"
import bcrypt from "bcryptjs"
import { createError } from "../utils/error.js";
import jwt from "jsonwebtoken";
import mongoose from 'mongoose';



export const register=async(req,res,next)=>{
    try{
        const salt=bcrypt.genSaltSync(10);
        const hash=bcrypt.hashSync(req.body.password,salt);
        const newUser=new User({
            ...req.body,
            password: hash,
        })
        await newUser.save()
        res.status(200).send("User has been created.")
    }catch(err){
        next(err);
    }
}

export const login = async (req, res, next) => {
    const { username, password } = req.body;

    // Log the requested username
   

    try {
        // Find the user by username
        console.log("Requested username:", username);
        const user = await User.findOne({ username });
        console.log("Requested username:", user);

        // If user not found, return 404 error
        if (!user) {
            return next(createError(404, "User not found"));
        }

        // Compare passwords
        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        // If password is incorrect, return 400 error
        if (!isPasswordCorrect) {
            return next(createError(400, "Wrong password"));
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user._id, isAdmin: user.isAdmin },
            process.env.JWT_SECRET
        );

        // Remove sensitive data from user object
        const { password: userPassword, isAdmin, ...otherDetails } = user.toObject();

        // Set JWT token in cookie
        res.cookie("access_token", token, { httpOnly: true });

        // Return user details and isAdmin status
        res.status(200).json({ details: { ...otherDetails }, isAdmin });
    } catch (err) {
        next(err);
    }
};

