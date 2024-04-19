const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocal = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const flash = require("express-flash");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const findOrCreate = require("mongoose-findorcreate");
require("dotenv").config();

const app = express();
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.use(
  session({
    secret: "Nani9963",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

mongoose
  .connect(
    "mongodb+srv://naveen:nani9963@cluster0.r1wiuvo.mongodb.net/TTUsersDB",
    { useNewUrlParser: true }
  )
  .then(() => {
    console.log("Data base Connected");
  });

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  githubId: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("user", userSchema);


passport.use(User.createStrategy());
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username });
  });
});
passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

// ##################################### Strategies
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/home",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({username:profile.displayName, googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FB_APP_ID,
      clientSecret: process.env.FB_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/home",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({username:profile.displayName, facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GIT_CLIENT_ID,
      clientSecret: process.env.GIT_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/github/home",
    },
    function (accessToken, refreshToken, profile, done) {
      User.findOrCreate({username:profile.displayName, githubId: profile.id }, function (err, user) {
        return done(err, user);
      });
    }
  )
);

//  #############################################################
app.get("/", (req, res) => {
  res.render("home", {users: null});
});
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
app.get(
  "/auth/google/home",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/home");
  }
);
app.get("/auth/facebook", passport.authenticate("facebook"));
app.get(
  "/auth/facebook/home",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/home");
  }
);
app.get("/auth/github", passport.authenticate("github"));
app.get(
  "/auth/github/home",
  passport.authenticate("github", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/home");
  }
);

app.get("/home", (req, res) => {
  if(req.isAuthenticated()){
    User.findOne({_id:req.user.id}).then((foundUser) => {
      const name = foundUser.username;
      res.render("home", {users: name});
    })
    
  }else{
    res.redirect("/login")
  }
  
});
app.get("/register", (req, res) => {
  res.render("register", { missing: req.flash("missing") });
});
app.get("/login", (req, res) => {
  res.render("login", { error: req.flash("error") });
});
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  // Basic validation
  if (!name || !email || !password) {
    req.flash("missing", "Missing required fields");
    return res.redirect("/register");
  }
  // Attempt to register the user
  User.register(
    { username: email, name: name },
    password,
    function (err, user) {
      if (err) {
        console.error("Error during registration:", err);
        return res.redirect("/register");
      }
      console.log("User registered successfully:");
      // Redirect to homepage or login page
      res.render("home", {users: user.name});
    }
  );
});
app.post("/login", (req, res) => {
  const newUser = new User({
    username: req.body.username,
    password: req.body.password,
  });
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      console.error(err);
      return res.redirect("/login");
    }
    if (!user) {
      // Authentication failed due to incorrect username or password
      req.flash("error", "Incorrect username or password."); // Flash error message
      return res.redirect("/login"); // Redirect to login page with flash message
    }
    // Authentication successful
    req.login(user, (err) => {
      if (err) {
        console.error(err);
        return res.redirect("/login");
      }
      return res.render("home", {users: user.name}); // Redirect to homepage upon successful login
    });
  })(req, res);
});

app.listen(3000, () => {
  console.log("Server Listening at 3000 🥳");
});
