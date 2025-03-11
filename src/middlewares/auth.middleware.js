import jwt from 'jsonwebtoken'
import User from '../models/user.model.js'

const verifyJWT = async function (req, res, next) {
    
    try {
        
        const token = req.cookies.accessToken

        if(!token) {
            return res.status(400).json({
                message: "unAuthorized request"
            })
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        console.log(decodedToken)
        
        const user = await User.findById(decodedToken?._id)

        if(!user) {
            return res.status(400).json({
                message: "Invalid Access Token"
            })
        }

        req.user = user
        next()

    } catch (error) {
        res.status(400).json({
            message: "Invalid Access Token",
            error,
        })
    }

}

export default verifyJWT