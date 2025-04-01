import User from '../models/user.model.js'
import crypto from 'crypto'
import nodemailer from 'nodemailer'
import jwt from 'jsonwebtoken'
import ApiResponse from '../utils/ApiResponse.js'
import ApiError from '../utils/ApiError.js'
import asyncHandler from '../utils/asyncHandler.js'

const generateAccessAndRefreshToken = async(userId) => {
    
    try {
        const user = await User.findById(userId)

        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave: false});

        return {accessToken, refreshToken};

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token.");
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body

    if (!name || !email || !password) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({ email })
    if (existedUser) {
        return res.status(401).json(new ApiResponse(401, null, "User already exists"))
    }

    const user = await User.create({
        name,
        email,
        password,
    })

    if (!user) {
        return res.status(400).json(new ApiResponse(400, null, "User not registered"))
    }

    const token = crypto.randomBytes(32).toString("hex")
    user.verificationToken = token

    await user.save()

    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_HOST,
        port: process.env.MAILTRAP_PORT,
        secure: false,
        auth: {
            user: process.env.MAILTRAP_USERNAME,
            pass: process.env.MAILTRAP_PASSWORD
        },
    });

    const mailOptions = {
        from: process.env.MAILTRAP_SENDERMAIL,
        to: user.email,
        subject: "Verify your email",
        text: `Please click on the following link: ${process.env.BASE_URL}/api/v1/users/verify/${token}`,
    }

    await transporter.sendMail(mailOptions);

    return res.status(201).json(new ApiResponse(200, user, "User registered successfully"))
})

const verifyUser = asyncHandler(async (req, res) => {
    const { token } = req.params

    if (!token) {
        throw new ApiError(400, "Invalid Token")
    }

    const user = await User.findOne({ verificationToken: token })

    if (!user) {
        throw new ApiError(400, "Invalid User")
    }

    user.isVerified = true
    user.verificationToken = undefined
    await user.save()

    return res.status(200).json(new ApiResponse(200, null, "User verified successfully"))
})

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findOne({ email })

    if (!user) {
        throw new ApiError(400, "Invalid email or password")
    }

    const passMatch = await user.isPasswordCorrect(password)

    if (!passMatch) {
        throw new ApiError(400, "Invalid password")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)

    const loggedUser = await User.findById(user._id).select("-password -refreshToken -verificationToken")

    const cookieOptions = {
        httpOnly: true,
        secure: true,
        maxAge: 24 * 60 * 60 * 1000
    }

    res.cookie("accessToken", accessToken, cookieOptions)
    res.cookie("refreshToken", refreshToken, cookieOptions)

    return res.status(200).json(new ApiResponse(200, loggedUser, "Login successful"))
})

const logout = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user?._id,
        {
            $unset: {
                refreshToken: 1,
            }
        },
        { new: true }
    )

    const cookieOptions = {
        httpOnly: true,
        secure: true,
    }

    res.clearCookie("accessToken", cookieOptions)
    res.clearCookie("refreshToken", cookieOptions)

    return res.status(200).json(new ApiResponse(200, null, "Logout successful"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    
    if (!incomingRefreshToken) {
        throw new ApiError(400, "Unauthorized request")
    }

    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

    const user = await User.findById(decodedToken?._id)

    if (!user) {
        throw new ApiError(400, "User not found")
    }

    if (incomingRefreshToken !== user?.refreshToken) {
        res.clearCookie("accessToken")
        res.clearCookie("refreshToken")
        throw new ApiError(400, "Token is used or expired")
    }

    const { accessToken, newRefreshToken } = await generateAccessAndRefreshToken(user._id)

    const cookieOptions = {
        httpOnly: true,
        secure: true,
        maxAge: 24 * 60 * 60 * 1000
    }

    user.refreshToken = newRefreshToken
    await user.save()

    res.cookie("accessToken", accessToken, cookieOptions)
    res.cookie("refreshToken", newRefreshToken, cookieOptions)

    return res.status(200).json(new ApiResponse(200, null, "Access token refreshed"))
})

const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body

    if (!email) {
        throw new ApiError(400, "Please provide email")
    }

    const user = await User.findOne({ email })

    if (!user) {
        throw new ApiError(400, "Invalid Email")
    }

    const token = crypto.randomBytes(32).toString("hex")
    user.resetPasswordToken = token
    user.resetPasswordExpires = Date.now() + 3600000 // 1 hour

    await user.save()

    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_HOST,
        port: process.env.MAILTRAP_PORT,
        secure: false,
        auth: {
            user: process.env.MAILTRAP_USERNAME,
            pass: process.env.MAILTRAP_PASSWORD
        },
    });

    const mailOptions = {
        from: process.env.MAILTRAP_SENDERMAIL,
        to: user.email,
        subject: "Reset your password",
        text: `Please click on the following link to reset password: ${process.env.BASE_URL}/api/v1/users/resetPassword/${token}`,
    }

    await transporter.sendMail(mailOptions)

    return res.status(201).json(new ApiResponse(200, null, "Reset mail sent"))
})

const resetPassword = asyncHandler(async (req, res) => {
    const { token } = req.params
    const { newPassword } = req.body

    if (!token) {
        throw new ApiError(400, "Invalid Token")
    }

    const user = await User.findOne({ resetPasswordToken: token })

    if (!user) {
        throw new ApiError(400, "Invalid User Token")
    }

    user.password = newPassword
    user.resetPasswordToken = undefined
    user.resetPasswordExpires = undefined
    await user.save()

    return res.status(200).json(new ApiResponse(200, null, "Password successfully reset"))
})

const currentUser = asyncHandler(async (req, res) => {
    const user = req.user

    if (!user) {
        throw new ApiError(404, "User not found")
    }

    return res.status(200).json(new ApiResponse(200, {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
    }, "User fetched successfully"))
})

export {
    registerUser,
    verifyUser,
    loginUser,
    logout,
    forgotPassword,
    resetPassword,
    currentUser,
    refreshAccessToken
}
