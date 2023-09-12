const mongoose = require("mongoose");

const passportlocalmongoose = require("passport-local-mongoose");

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const findOrCreate = require('mongoose-findorcreate');

const passport = require("passport");

const session = require('express-session');

mongoose.connect("mongodb://localhost:27017/chatrooms");




const userschema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    otp: String,

    private_rooms: [{ room_name: String, room_id: String }],
    public_rooms: [{ room_name: String }],

});
const roomschema = new mongoose.Schema({
    private_room_name: String,
    private_room_id: String,
    active_users: [{ user: String }]

});

userschema.plugin(passportlocalmongoose); //automatically do hash+salt our passwords

userschema.plugin(findOrCreate);
console.log("sjdnfvjsdfnhjfebn");

const usermodel = mongoose.model("user", userschema);
const roommodel = mongoose.model("privateroom", roomschema);

passport.use(usermodel.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    usermodel.findById(id, function(err, user) {
        done(err, user);
    });
});
passport.use(new GoogleStrategy({

        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/callback",


    },
    function(accessToken, refreshToken, profile, cb) {

        usermodel.findOrCreate({ username: profile.displayName }, function(err, user) {


            return cb(err, user);
        });




    }
));
module.exports = {
    User: usermodel,
    Privateroom: roommodel

}