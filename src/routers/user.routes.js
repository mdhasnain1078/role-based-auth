import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../model/user.js";
import { authMiddleware, roleMiddleware } from "../middleware/auth.js";

const router = express.Router();
const SECRET = process.env.JWT_SECRET || "supersecretkey";

// 🔹 Helper function to create token
const createToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role },
    SECRET,
    { expiresIn: "1h" }
  );
};

// ================== REGISTER ==================
router.get("/register", (req, res) => {
  res.render("register.ejs");
});

router.post("/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render("error.ejs", { message: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username, email, password: hashed, role });

    // Auto-login after registration (optional)
    const token = createToken(newUser);
    res.cookie("token", token, { httpOnly: true });

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.render("error.ejs", { message: "Registration failed" });
  }
});

// ================== LOGIN ==================
router.get("/login", (req, res) => {
  res.render("login.ejs");
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const foundUser = await User.findOne({ email });

    if (!foundUser) {
      return res.render("error.ejs", { message: "User not found" });
    }

    const match = await bcrypt.compare(password, foundUser.password);
    if (!match) {
      return res.render("error.ejs", { message: "Invalid credentials" });
    }

    const token = createToken(foundUser);
    res.cookie("token", token, { httpOnly: true });

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.render("error.ejs", { message: "Login failed" });
  }
});

// ================== DASHBOARD ==================
router.get("/dashboard", authMiddleware, (req, res) => {
  res.render("dashboard.ejs", { user: req.user });
});

// ================== ADMIN ONLY ==================
router.get("/admin", authMiddleware, roleMiddleware("admin"), (req, res) => {
  res.render("admin.ejs", { user: req.user });
});

// ================== LOGOUT ==================
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

export default router;
