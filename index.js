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

mongoose.connect("mongodb+srv://sashankgopalam:n9Pv91YNnFdqThuq@todolistsample.eg5h3tx.mongodb.net/?retryWrites=true&w=majority&appName=todolistsample");

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
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  const { name, username, password } = req.body;

  if (!isValidEmail(username)) {
    return res.render("register", { error: "Invalid email format." });
  }

  if (!isValidPassword(password)) {
    return res.render("register", { error: "Password must be 6–8 characters, include uppercase, lowercase, and a number." });
  }

  try {
    const existingUser = await User.findOne({ email: username });
    if (existingUser) {
      return res.render("register", { error: "User already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const newUser = new User({ name, email: username, password: hashedPassword });
    await newUser.save();
    res.redirect("/login");
  } catch (err) {
    console.log(err);
    res.render("register", { error: "Error during registration." });
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: null, success: req.query.success || null });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!isValidEmail(username)) {
    return res.render("login", { error: "Invalid email format.", success: null });
  }

  try {
    const foundUser = await User.findOne({ email: username });
    if (foundUser && await bcrypt.compare(password, foundUser.password)) {
      const token = jwt.sign({ id: foundUser._id, name: foundUser.name, email: foundUser.email }, JWT_SECRET, { expiresIn: '1h' });
      res.cookie('token', token, { httpOnly: true, secure: false });
      res.redirect("/secrets");
    } else {
      res.render("login", { error: "Invalid credentials.", success: null });
    }
  } catch (err) {
    console.log(err);
    res.render("login", { error: "Login failed.", success: null });
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
