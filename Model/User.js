const moongoose = require("mongoose");
const UserSchema = new moongoose.Schema(
    {
        name: { type: String },
        email: { type: String },
        phone: { type: String },
        password: { type: String, select: false },
        googleId: { 
            type: String, 
            unique: true, 
            sparse: true, //allows null values for non-OAuth users 
        },
        oauthProvider: {
            type: String,
            enum: ["google", "none"],
            default: "none"
        }
    },
    { timestamps: true }
);

module.exports = moongoose.model("User", UserSchema);