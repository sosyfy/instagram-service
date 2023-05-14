import express from "express";

import { body, validationResult } from "express-validator";
import { login, logout, register } from "../services/authService.js";
import parseError from "../utils/parseError.js";
import { isGuest } from "../middlewares/guards.js";
import randomNumber from "../utils/randomNumber.js";

const router = express.Router()

async function authAction(req, res, action, httpErrorStatus) {
	const formData = req.body;
	console.log("formData", formData)
    
	try {
		const { errors } = validationResult(req)
        
		if( errors.length > 0 ) {
			throw errors;
		}
        
		let data;
        
		if( action === "login" ) {
			data = await login(formData.email, formData.password)
		} else if( action === "register" ) {
			let otp = randomNumber(4);
			data = await register(formData.email, formData.password, otp)
		}

		res.json(data);

	} catch ( error ) {
		const message = parseError(error)
        
		//400 - bad request
		res.status(httpErrorStatus).json({
			message
		})
	}
}

router.post("/login",
	isGuest(),
	body("email")
		.notEmpty()
		.withMessage("Email should be specified")
		.bail()
		.isEmail()
		.withMessage("Please enter a valid email address!")
		.bail()
		.isLength({ min: 6 })
		.withMessage("Email must be at least 6 characters long!"),
	body("password")
		.isLength({min: 6})
		.withMessage("Password must be at least 6 characters long!"),
	async(req, res) => {
		await authAction(req, res, "login", 400)
	})

router.post("/register", 
	isGuest(),
	body("email")
		.notEmpty()
		.withMessage("Email should be specified")
		.bail()
		.isEmail()
		.withMessage("Please enter a valid email address!")
		.isLength({ min: 6 })
		.withMessage("Email must be at least 6 characters long!"),
	body("password")
		.isLength({min: 6})
		.withMessage("Password must be at least 6 characters long!"),
	body("confirmPassword")
		.custom((value, {req}) => {
			return value.trim() === req.body.password
		})
		.withMessage("Password don't match!"),
	async (req, res) => {
		await authAction(req, res, "register", 400)
	})

router.get("/logout", async (req, res) => {
	const token = req.token;
    
	await logout(token);
    
	res.status(204).end();//204 - no content
})



export default router;
