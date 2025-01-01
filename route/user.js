const User = require("../Model/User");
const router = require("express").Router();
// const Cryptojs = require("crypto-js");
const jwt = require("jsonwebtoken"); 
const express = require("express");
const passport = require("passport");
const { SALT_ROUNDS } = require("../config");
const bcrypt = require("bcrypt");

//registration for non-oauth users
router.post("/registration", async (req, res) => {
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
});

//Login for non-oauth users
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email }).select("+password");
        console.log("User found", user);

        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }

        console.log("oauthProvider:", user.oauthProvider);
        if (user.oauthProvider !== "none") {
            return res.status(400).json({ error: " OAuth provider not supported for this action" });
        }

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
});

//OAuth login
router.get(
    "/auth/google",
    (req, res, next) => {
        console.log("Starting Google Oauth login process...");
        next();
    },
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

//OAuth Callback
router.get(
    "/auth/google/callback",
    (req, res, next) => {
        console.log("Google OAuth callback invoked with:", req.query);
        next();
    },
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        console.log("User authenticated:", req.user);
        //successful authentication
        res.redirect("/dashboard");
    }
);

//Get all users
router.get("/", async (req, res) => {
    try {
        const user = await User.find();
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json(error);
    }
});

//Get one user
router.get("/find/:id", async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json(error);
    }
});

//Update user
router.put("/put/:id", async (req, res) => {
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
});

//Delet user
router.delete("/delete/:id", async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(200).json("User deleted successfully");
    } catch (error) {
        res.status(500).json(error);
    }
});

module.exports = router;






























