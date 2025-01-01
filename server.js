const moongoose = require("mongoose");
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require("passport");
const session = require("express-session");
require("./passport"); // import the passport configuration

const userRoute = require("./route/user");

const app = express();
dotenv.config();

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
    })
);
app.use(passport.initialize());
app.use(passport.session());


app.use(express.json());
app.use(cors());

moongoose
    .connect(process.env.MONGODB_API)
    .then((console.log("DB connected successfully")));

app.use("/api/user", userRoute);

app.listen(2020, () => {
    console.log("server is running")
});