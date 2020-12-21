const express = require('express');
const router = express.Router();
// Require user model
const User = require("./../models/User.model");

// Add bcrypt to encrypt passwords
const bcrypt = require('bcrypt');
const bcryptSalt = 10;
// Add passport
const passport = require('passport')

const ensureLogin = require('connect-ensure-login');

router.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render('passport/private', { user: req.user });
});

//iteration 1: The signup feature
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
})

//create a new user
router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;
  console.log(username, password)

  //check inputs are not empty and show error message
  if (!username && !password) {
    res.render("auth/signup", { errorMessageUserName: 'Username is required', errorMessagePassword: 'Password is required' });
  } else if (!password) {
    res.render("auth/signup", { errorMessagePassword: 'Password is required' });
  } else if (!username) {
    res.render("auth/signup", { errorMessageUserName: 'Username is required' });
  }
  //make sure password is strong
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test((password))) {
    res.render("auth/signup", { errorMessagePassword: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' })
  };

  //check user does not already exist
  console.log({ username })
  User.findOne({ username:username })
    .then(user => {
      if (user) {
        res.render('auth/signup', { errorMessage: 'This username already exists' })
        return
      }
      bcrypt.genSalt(bcryptSalt)
        .then(salt => {
          bcrypt.hash(password, salt)
            .then(hashedPwd => {
              const newUser = {
                username:username,
                password: hashedPwd
              }
              User.create(newUser)
                .then(createdUser => {
                  res.redirect('/private-page')
                })
                .catch(err=> {
                  console.error(err)
                  res.send(err)
                })
            })
        })

    })
    .catch(err=> {
      console.error(err)
      res.send(err)
    })
})

//Iteration 2 : The login feature
router.get('/login', (req, res) => {
  res.render("auth/login", { "errorMessage": req.flash("error") });
})

router.post('/login', passport.authenticate('local', {
  successRedirect: '/private-page',
  failureRedirect: '/login',
  failureFlash: true
}))

//Logout
router.get('/logout', (req, res, next) => {
  req.logout()
  res.redirect('/login')
})

//Iteration 3: Private page

router.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  if (!req.user) {
    res.redirect("/login");
    return;
  }
  res.render("auth/private", { user: req.user })
})
module.exports = router;
