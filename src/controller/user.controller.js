import User from '../models/user.model.js'
import crypto from 'crypto'
import nodemailer from 'nodemailer'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const registerUser = async (req, res) => {

    const { name, email, password } = req.body

    if (!name || !email || !password) {
        return res.status(400).json({
            message: "All fields are required",
        });
    }

    try {

        const existedUser = await User.findOne({email})

        if (existedUser) {
            return res.status(401).json({
                message: "User already exists"
            })
        }

        const user = await User.create({
            name,
            email,
            password,
        })

        if (!user) {
            return res.status(400).json({
                message: "User not registered"
            })
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
            subject: "Verify your email", // Subject line
            text: `Please click on the following link: ${process.env.BASE_URL}/api/v1/users/verify/${token}`,
        }

        await transporter.sendMail(mailOptions);

        res.status(201).json({
            message: "User register Successfully",
            success: true
        })

    } catch (error) {
        res.status(400).json({
            message: "User not register, something wrong",
            error,
            success: false
        })
    }
}

const verifyUser = async function (req, res) {

    const { token } = req.params;

    if (!token) {
        return res.status(400).json({
            message: "Invalid TOken"
        })
    }

    const user = await User.findOne({ verificationToken: token })

    if (!user) {
        return res.status(400).json({
            message: "Invalid User"
        })
    }

    user.isVerified = true,
    user.verificationToken = undefined
    user.save()

    res.status(200).json({
        message: "Verified",
        success: true
    })
}

const loginUser = async function (req, res) {

    const { email, password } = req.body

    if (!email || !password) {
        return res.status(400).json({
            message: "All Fields are required"
        })
    }

    try {

        const user = await User.findOne({ email })

        if (!user) {
            return res.status(400).json({
                message: "Invalid email or password"
            })
        }

        const passMatch = await bcrypt.compare(password, user.password)

        if (!passMatch) {
            return res.status(400).json({
                message: "Invalid password"
            })
        }

        const accessToken = jwt.sign({
            _id: user._id,
            role: user.role,
        },
            process.env.ACCESS_TOKEN_SECRET,
            {
                expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
            },
        )

        const refreshToken = jwt.sign({
            _id: user._id,
        },
            process.env.REFRESH_TOKEN_SECRET,
            {
                expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
            },
        )

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave: false})

        const loggedUser = await User.findById(user._id).select("-password -refreshToken -verificationToken")

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            maxAge: 24*60*60*1000
        }

        res.cookie("accessToken", accessToken, cookieOptions)
        res.cookie("refreshToken", refreshToken, cookieOptions)

        res.status(200).json({
            message: "Login Successfully",
            user: loggedUser, 
            success: true,
        })


    } catch (error) {
        console.log(error)
        res.status(400).json({
            message: "Failed to Login",
            error,
            success: false
        })
    }

}

const logout = async function (req, res) {
    
    try {
        await User.findByIdAndUpdate(
            req.user?._id, 
            {
                $unset: {
                    refreshToken: 1,
                }
            },
            {new: true}
        )
    
        const cookieOptions = {
            httpOnly: true,
            secure: true,
        }
    
        res.clearCookie("accessToken", cookieOptions)
        res.clearCookie("refreshToken", cookieOptions)
    
        res.status(200).json({
            message: "logout successfully",
            success: true,
        })
    } catch (error) {
        res.status(400).json({
            message: "failed to logout",
            error,
            success: false
        })
    }
}

const forgotPassword = async function (req, res) {
    
    const {email} = req.body

    if(!email) {
        return res.status(400).json({
            message: "Please provide email"
        })
    }

    try {
        const user = await User.findOne({email})
    
        if(!user) {
            return res.status(400).json({
                message: "Invalid Email"
            })
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
                subject: "Verify your email", // Subject line
                text: `Please click on the following link to reset password: ${process.env.BASE_URL}/api/v1/users/resetPassword/${token}`,
            }
    
            await transporter.sendMail(mailOptions);

            res.status(201).json({
                message: "Reset Mail sended",
                success: true
            })

    } catch (error) {
        res.status(400).json({
            message: "Something went wrong while sending mail",
            error,
            success: false
        })
    }
}

const resetPassword = async function (req, res) {
    
    const {token} = req.params
    const {newPassword} = req.body

    if (!token) {
        return res.status(400).json({
            message: "Invalid Token"
        })
    }

    const user = await User.findOne({resetPasswordToken: token})

    if (!user) {
        return res.status(400).json({
            message: "Invalid User Token"
        })
    }

    user.password = newPassword;
    user.resetPasswordToken = undefined
    user.resetPasswordExpires = undefined
    user.save()

    res.status(200).json({
        message: "Password successfully reset",
        success: true,
    });

}

const currentUser = async function (req, res) {
    try {
        const user = req.user;

        if (!user) {
            return res.status(404).json({
                message: "User not found",
                success: false
            });
        }

        res.status(200).json({
            message: "User fetched successfully",
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                isVerified: user.isVerified
            },
            success: true
        });
    } catch (error) {
        res.status(400).json({
            message: "Failed to fetch user",
            error,
            success: false
        });
    }
};


export {
    registerUser,
    verifyUser,
    loginUser,
    logout,
    forgotPassword,
    resetPassword,
    currentUser,
}