const User = require("../Model/User");
const router = require("express").Router();
// const Cryptojs = require("crypto-js");
const jwt = require("jsonwebtoken"); 
const express = require("express");
const passport = require("passport");
const { SALT_ROUNDS } = require("../config");
const bcrypt = require("bcrypt");

//registration for non-oauth users
exports.registerUser = async (req, res) => {
    try {
        const { name, email, password} = req.body;

        // Check if all required fields are provided
        if (!name || !email || !password) {
            return res.status(400).json({ error: "All fields are required "});
        }

        //Check if email is already in use
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: "Email is already in use" });

        //Hash the password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        //Create and save the new user
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully" });

    } catch (error) {
        console.error("Registration error:", error);//log error for debugging
        res.status(500).json({ error: "server error" });
    }
};

//Login for non-oauth users
exports.loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email }).select("+password");
        console.log("User found", user);

        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }

        console.log("oauthProvider:", user.oauthProvider);
        if (user.oauthProvider !== "none") {
            return res.status(400).json({ error: " OAuth provider not supported for this action" });
        }

        //compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        console.log("Password match status, isMatch");

        if (!isMatch) return res.status(400).json({ error: "wrong password" });


        if(!process.env.JWT_SECRET){
            console.error("JWT_SECRET not defined");
            return res.status(500).json({ error: "Server configuration issue" });
        }


        const token = jwt.sign(
            { id: user._id}, 
            process.env.JWT_SECRET,
            { expiresIn: "3d" },
        );

        res.status(200).json({ token, user });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Server error" });
    }
};

//OAuth login
exports.startGoogleLogin = (req, res, next) => {
    console.log("Starting Google login process...");
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })(req, res, next);
};

//OAuth Callback
exports.googleCallback = (req, res, next) => {
    console.log("Google OAuth callback invoked with:", req.query);
    passport.authenticate("google", { failureRedirect: "/login" }, (err, user, info) => {
        if (err || !user) {
            console.error("OAuth Error:", err || info);
            return res.redirect("/login");
        }
        req.logIn(user, (loginErr) => {
            if (loginErr) {
                console.error("Login Error:", loginErr);
                return res.redirect("/login");
            }
            console.log("User authenticated:", user);
            res.redirect("/dashboard");
        });
    })(req, res, next);
};

//Github login
exports.startGithubLogin = (req, res, next) => {
    console.log("Starting Github login process...");
    passport.authenticate("github", { scope: ["user:email"] })(req, res, next);
};

//Github call back
exports.githubCallback = (req, res, next) => {
    console.log("processing github callback"); //check if route is accessed
    passport.authenticate("github", (err, user, info) => {
        if (err) {
            console.error("error during github callback:", err);
            return res.status(500).json({ error: "Authentication failed" });
        }

        if (!user) {
            console.error("No user returned from github");
            return res.status(401).json({ error: "Authentication failed." });
        }

        //log user in
        req.logIn(user, (err) => {
            if (err) {
                console.error("error logging in user:", err);
                return res.status(500).json({ error: "Session creation failed." });
            }

            console.log("User successfully authenticated:", user);
            return res.redirect("/dashboard");
        });
    })(req, res, next);
};

//Get all users
exports.getAllUsers = async (req, res) => {
    try {
        const user = await User.find();
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json(error);
    }
};



//Get one user
exports.getUserById = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json(error);
    }
};



//Update user
exports.updateUser = async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(
            req.params.id,
            {
                $set: req.body,
            },
            { new: true },
        );
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json(error);
    }
};

//Delete user
exports.deleteUser = async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(200).json("User deleted successfully");
    } catch (error) {
        res.status(500).json(error);
    }
};
