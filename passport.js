const User = require("../CSS/Model/User")
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

//load environment variables
require("dotenv").config();

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "http://localhost:2020/api/user/auth/google/callback",
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                // Check if User already exists
                let user = await User.findOne({ googleId: profile.id });

                if (!user) {
                    // create new user if not found
                    user = await User.create({
                        name: profile.displayName,
                        email: profile.emails[0].value,
                        googleId: profile.id,
                        oauthProvider: "google",
                    });
                }

                return done(null, user);

            }catch (error) {
                return done(error, null);
            }
        }
    )
);

// serialize user instance to session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

//Deserialize user instance from session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});