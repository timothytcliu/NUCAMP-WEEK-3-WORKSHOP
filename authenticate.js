const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;  //provides helper methods such as extracting Jw token from a request object
const jwt = require('jsonwebtoken');   //node modules used to create/sign/verify tokens

const config = require('./config.js');

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = user => {
    return jwt.sign(user, config.secretKey, {expiresIn: 3600});
};

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();  //token is to be extracted from authorization header
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(
    new JwtStrategy(
        opts,
        //function verify(jwt_payload, done)
        (jwt_payload, done) => {
            console.log('JWT payload:', jwt_payload);
            User.findOne({_id: jwt_payload._id}, (err, user) => {
                if (err) {
                    return done(err, false);  
                } else if (user) {
                    return done(null, user);  //passport uses done callback to access the user document and load the info to request object (done from passport-jwt module, it is written for us)
                } else {
                    return done(null, false);  //when no error, but also no user was found
                }
            });
        }
    )
);

exports.verifyUser = passport.authenticate('jwt', {session: false});

exports.verifyAdmin = function(req, res, next) {
    if (req.user.admin === true) {
        return next();
    } else {
        const err = new Error('You are not authorized to perform this operation!');
        res.statusCode = 403;
        return next(err);
    }
}