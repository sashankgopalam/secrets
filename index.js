const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const JWT_SECRET = "super_secure_jwt_secret_key"; 
const SALT_ROUNDS = 10;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

mongoose.connect("mongodb://localhost:27017/secrets");

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});

const User = mongoose.model("User", userSchema);

function isValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}


function isValidPassword(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,8}$/.test(password);
}


function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.redirect("/login");
    req.user = user;
    next();
  });
}

// Routes
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, username, password } = req.body;

  if (!isValidEmail(username)) {
    return res.send("Invalid email format.");
  }

  if (!isValidPassword(password)) {
    return res.send("Password must be 6–8 characters, include uppercase, lowercase, and a number.");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const newUser = new User({
      name,
      email: username,
      password: hashedPassword
    });
    await newUser.save();
    res.redirect("/login");
  } catch (err) {
    console.log(err);
    res.send("Error during registration.");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!isValidEmail(username)) {
    return res.send("Invalid email format.");
  }

  try {
    const foundUser = await User.findOne({ email: username });
    if (foundUser && await bcrypt.compare(password, foundUser.password)) {
      const token = jwt.sign({ id: foundUser._id, name: foundUser.name, email: foundUser.email }, JWT_SECRET, { expiresIn: '1h' });
      res.cookie('token', token, { httpOnly: true, secure: false }); // Set `secure: true` in production
      res.redirect("/secrets");
    } else {
      res.send("Invalid credentials.");
    }
  } catch (err) {
    console.log(err);
    res.send("Login failed.");
  }
});

app.get("/secrets", authenticateToken, (req, res) => {
  res.render("secrets", { user: req.user });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

app.listen(5000, () => {
  console.log("Server Started on port 5000");
});
