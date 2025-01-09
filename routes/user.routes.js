import { Router } from "express";
import {
    loginUser, registerUser, changeCurrentPassword, forgetPassword, resetPassword,
} from "../controllers/user.controller.js"
import {verifyJWT} from "../middlewares/auth.middleware.js"

const userRouter = Router();

userRouter.route("/register").post(registerUser
)

userRouter.route("/login").post(
    loginUser
)




userRouter.route("/changePassword").post(
    verifyJWT,
    changeCurrentPassword
)

userRouter.route("/forgetPassword").post(
    forgetPassword
)

userRouter.route("/resetPassword/:tokenId").post(
    resetPassword
)


export default userRouter