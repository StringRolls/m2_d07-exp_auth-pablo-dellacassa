// routes/auth.routes.js

const { Router } = require("express");
const router = new Router();

const bcrypt = require("bcrypt");
const saltRounds = 5;

const User = require("../models/User.model");
const res = require("express/lib/response");

// GET route ==> to display the signup form to users
router
  .route("/signup")
  .get((req, res) => res.render("auth/signup"))
  // POST route ==> to process form data
  .post((req, res, next) => {
    // console.log("The form data: ", req.body);

  const { username, email, password } = req.body;
  /*
  if(!username || !email || !password) {
    res.render("auth/login", {errorMessage: "All fields required"})
    return
  } // After this line I know I have username, email and password that are not "undefined"

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/
  if(regex.test(password)){
    res.render("auth/login", {errorMessage: "Password must follow guidelines"})
    return
  }
  */
  bcrypt
    .genSalt(saltRounds)
    .then((salt) => bcrypt.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        // username: username
        username,
        email,
        // passwordHash => this is the key from the User model
        //     ^
        //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
        passwordHash: hashedPassword,
      })
    })
    .then((userFromDB) => {
      // console.log("Newly created user is: ", userFromDB);
      res.redirect("/");
    })
    .catch((err) => res.status(500).render("auth/signup", { errorMessage: err.message }))    
    .catch((err) => next(err));
});

router
  .route("/login")
  .get((req, res) => res.render("auth/login"))
  .post((req, res) => {
    const { email, password } = req.body;

    User.findOne({ email })
      .then((user) => {
        if (!user) {
          res.render("auth/login", { errorMessage: "Wrong credentials!" });
          return;
        } else {
          if (bcrypt.compareSync(password, user.passwordHash)) {
            req.session.currentUser = user;
            res.redirect("/userProfile"); // redirect to wherever you want
            return;
          } else {
            res.render("auth/login", { errorMessage: "Wrong credentials!" });
          }
        }
      })
      .catch((err) => console.log(err));
  });


module.exports = router;
