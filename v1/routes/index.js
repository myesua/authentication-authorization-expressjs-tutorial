import express from "express";
import { Verify, VerifyRole } from "../middleware/verify.js";
import Auth from "./auth.js";

const app = express();

app.disable("x-powered-by"); //Reduce fingerprinting
app.get("/favico.ico", (req, res) => {
	res.sendStatus(404);
});
app.get("/v1", (req, res) => {
	try {
		res.set("Content-Security-Policy", "default-src 'self'");
		res.status(200).json({
			status: "success",
			data: [],
			message: "Welcome to our API homepage!",
		});
	} catch (err) {
		res.status(500).json({
			status: "error",
			message: "Internal Server Error",
		});
	}
});
app.use("/v1/auth", Auth);
app.get("/v1/user", Verify, (req, res) => {
	res.status(200).json({
		status: "success",
		message: "Welcome to your Dashboard!",
	});
});
app.get("/v1/admin", Verify, VerifyRole, (req, res) => {
	res.status(200).json({
		status: "success",
		message: "Welcome to the Admin portal!",
	});
});
export default app;
