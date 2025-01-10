import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import { User} from "../models/user.models.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";
import nodemailer from "nodemailer"
import bycrypt from "bcrypt";



const generateAccessTokens = async(userId)=>{
    try{
        const user = await User.findById(userId)
       
        const accessToken = user.generateAccessToken()

        await user.save({validateBeforeSave: false})

        return {accessToken}

    }catch(error){
        throw new ApiError(500, "Something went wrong while generating access token")
    }
}

const registerUser = asyncHandler(async(req, res)=>{

    try {
        const {name, email, password} = req.body;
        const existedUser = await User.findOne({ name })

        if (existedUser) {
            console.log(existedUser);
            throw new ApiError(409, "User with email already exists")
            
        }

        const user = await User.create({name, email, password})
        const createdUser = await User.findById(user._id).select(
            "-password"
           )
        res.status(201).json(createdUser);
    } catch (error) {
        console.log("Outside try block",error.message)
        res.status(500).json({ error: error.message });
    }

    
});

const loginUser = asyncHandler( async (req, res) => {
    try {
        const { name, password } = req.body;
        const user = await User.findOne({name});
        
        if (!user) {
            throw new ApiError(404,'User Does Not Exist!')
        }

        const isMatch = await user.isPasswordCorrect(password);
        if (!isMatch) {
            throw new ApiError(401,"Invalid credentials!")
        } 

        const {accessToken} = await generateAccessTokens(user._id)
        
        const loggedInUser = await User.findById(user._id).
        select("-password")

        const accessTokenOptions = {
            httpOnly: true,
            secure: true,
            expires: new Date(Date.now() + 86400 * 1000)
        }
        

        return res
        .status(200)
        .cookie("accessToken", accessToken, accessTokenOptions)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser, accessToken
                },
                "User logged in succeessfully"
            )
        )


    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



const changeCurrentPassword = asyncHandler(async(req, res) => {
    const {oldPassword, newPassword} = req.body    

    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"))
})


const forgetPassword = asyncHandler(async (req, res) => {
    try {
      const user = await User.findOne({ email: req.body.email });
  
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }
  
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET_KEY, {expiresIn: "10m",});
      
      const transporter =  nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD_APP_EMAIL,
        },
      });
  
      const mailOptions = {
        from: process.env.EMAIL,
        to: req.body.email,
        subject: "Reset Password",
        html: `<h1>Reset Your Password</h1>
      <p>Token ${token}</p>
      <p>The link will expire in 10 minutes.</p>
      <p>If you didn't request a password reset, please ignore this email.</p>`,
      };
  
      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          return res.status(500).send({ message: err.message });
        }
        res.status(200).send({ message: "Email sent" });
      });
    } catch (err) {
      res.status(500).send({ message: err.message });
    }
})



const resetPassword = asyncHandler(async (req, res) => {
    try {
        const {tokenId} = req.params
      const decodedToken = jwt.verify(
        tokenId,
        process.env.JWT_SECRET_KEY
      );
  
      if (!decodedToken) {
        return res.status(401).send({ message: "Invalid token" });
      }
  
      const user = await User.findOne({ _id: decodedToken.userId });
      console.log("user",user);
      if (!user) {
        return res.status(401).send({ message: "no user found" });
      }
      
  
      user.password = req.body.newPassword;
      await user.save();
  
      res.status(200).send({ message: "Password updated" });
    } catch (err) {
      res.status(500).send({ message: err.message });
    }
})




export {
    registerUser,
    loginUser,
    changeCurrentPassword,
    forgetPassword,
    resetPassword,

}