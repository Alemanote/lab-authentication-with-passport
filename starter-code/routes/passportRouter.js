const express        = require("express");
const router         = express.Router();
// User model
const User           = require("../models/user");
// Bcrypt to encrypt passwords
const bcrypt         = require("bcrypt");
const bcryptSalt     = 10;
const ensureLogin = require("connect-ensure-login");
const passport      = require("passport");



router.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});

router.get("/signup", (req, res, next) => {
  res.render("passport/signup");
});


//LOGIN

router.post("/signup", (req, res, next) => {
  var username = req.body.username;
  var password = req.body.password;

  if (username === "" || password === "") {
    res.render("passport/signup", {
      errorMessage: "Indicate a username and a password to sign up"
    });
    return;
  }

  User.findOne({ "username": username }, "username", (err, user) => {
    if (user !== null) {
      res.render("passport/signup", {
        errorMessage: "The username already exists"
      });
      return;
    }

    var salt     = bcrypt.genSaltSync(bcryptSalt);
    var hashPass = bcrypt.hashSync(password, salt);

    var newUser = User({
      username,
      password: hashPass
    });

    newUser.save((err) => {
      if (err) {
        res.render("passport/signup", {
          errorMessage: "Something went wrong when signing up"
        });
      } else {
        res.redirect("/login");
      }
    });
  });
});


module.exports = router;


router.get("/login", (req, res, next) => {
  res.render("passport/login");
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/private-page",
  failureRedirect: "/login",
  failureFlash: true,
  passReqToCallback: true
}));

// router.post("/login", (req, res, next) => {
//   var username = req.body.username;
//   var password = req.body.password;

//  if (username === "" || password === "") {
//     res.render("passport/login", {
//       errorMessage: "Indicate a username and a password to log in"
//     });
//     return;
//   }

//  User.findOne({ "username": username },
//     "_id username password following",
//     (err, user) => {
//       if (err || !user) {
//         res.render("passport/login", {
//           errorMessage: "The username doesn’t exist"
//         });
//         return;
//       } else {
//         if (bcrypt.compareSync(password, user.password)) {
//           req.session.currentUser = user;
//           // res.redirect(“/tweets”);
//           // logged in
//         } else {
//           res.render("passport/login", {
//             errorMessage: "Incorrect password"
//           });
//         }
//       }
//   });
// });

