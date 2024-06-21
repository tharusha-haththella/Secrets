import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

//creating a session
app.use(
  session({
    secret: process.env.SESSION_SECRET, //like key
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, //max age = a daay
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", async (req, res) => {
  //console.log(req.user);
  if (req.isAuthenticated()) {
    //TODO: Update this to pull in the user secret to render in secrets.ejs
    try {
      const email = req.user.email;
      await db.query(
        "SELECT secret FROM users WHERE email = ?",
        [email],
        (error, results, fields) => {
          const secret = results[0].secret;
          if (secret) {
            res.render("secrets.ejs", { secret: secret });
          } else {
            res.render("secrets.ejs", { secret: "You should submit a secret!" });
          }
        }
      );
    } catch (error) {
      console.log(error);
    }
  } else {
    res.redirect("/login");
  }
});

//TODO: Add a get route for the submit button
//Think about how the logic should work with authentication.
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    //to check whether the email already exists
    await db.query(
      "SELECT * FROM users WHERE email = ?",
      email,
      async (error, results, fields) => {
        if (results.length > 0) {
          //results.length = gives the output of the query
          res.send("Email already exists. Try logging in.");
        } else {
          //hashing the password
          bcrypt.hash(password, saltRounds, async (err, hash) => {
            if (err) {
              console.log("Error in hashing");
            } else {
              const sql = "INSERT INTO users (email, password) VALUES (?)";
              const userdata = [email, hash];
              //registering user and hashed password into database
              await db.query(sql, [userdata], (err, data) => {
                if (err) {
                  return res.json(err.message);
                } else {
                  return "Query executed successfully";
                }
              });
              //after successful registration redirecting to the login page
              res.redirect("/login");
            }
          });
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

//TODO: Create the post route for submit.
//Handle the submitted data and add it to the database
app.post("/submit", async (req, res) => {
  const secret = req.body.secret;
  const email = req.user.email;

  try {
    await db.query("UPDATE users SET secret = ? WHERE email = ?", [
      secret,
      email,
    ]);
    res.redirect("/secrets");
  } catch (error) {
    console.log(error);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    //console.log(username);

    try {
      await db.query(
        "SELECT * FROM users WHERE email = ?",
        username,
        async (error, results, fields) => {
          const user = results[0];
          if (results.length > 0) {
            bcrypt.compare(password, user.password, (err, valid) => {
              if (err) {
                return cb(err);
              } else {
                if (valid) {
                  return cb(null, user);
                } else {
                  return cb("Invalid Password");
                }
              }
            });
          } else {
            return cb("User not found");
          }
        }
      );
    } catch (error) {
      console.log(error);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      //console.log(profile);
      try {
        await db.query(
          "SELECT * FROM users WHERE email = ?",
          profile.email,
          async (error, results, fields) => {
            //console.log(results.length);
            if (results.length === 0) {
              const data = [profile.email, "google"];
              console.log(data);
              await db.query(
                "INSERT INTO users (email, password) VALUES (?)",
                [data],
                async (error, result, fields) => {
                  //const user = result[0];
                  if (result.affectedRows === 1) {
                    await db.query(
                      "SELECT * FROM users WHERE email = ?",
                      profile.email,
                      async (error, users, fields) => {
                        const user = users[0];
                        cb(null, user);
                      }
                    );
                  } else {
                    console.log(error);
                  }
                }
              );
            } else {
              const existing_user = results[0];
              cb(null, existing_user);
            }
          }
        );
      } catch (error) {
        cb(error);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
