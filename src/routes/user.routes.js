import express from "express"
import { 
    currentUser,
    forgotPassword,
    loginUser, 
    logout, 
    refreshAccessToken, 
    registerUser, 
    resetPassword, 
    verifyUser,
} from "../controller/user.controller.js"

import verifyJWT from "../middlewares/auth.middleware.js"

const router = express.Router()

router.post('/register', registerUser)
router.get('/verify/:token', verifyUser)
router.post('/refresh-token', refreshAccessToken)
router.post('/login', loginUser)
router.post('/logout', verifyJWT, logout)
router.post('/forgotPassword', forgotPassword)
router.post('/resetPassword/:token', resetPassword)
router.get('/currentUser', verifyJWT, currentUser);

export default router