const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const morgan = require("morgan");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const path = require("path");
dotenv.config();
const app = express();

// Middleware
app.use(cors({
  origin: "https://neurophi.tech",
  credentials: true, // Allow cookies
}));
app.use(express.json());
app.use(cookieParser());
app.use(morgan("combined")); // Logging
app.use(express.static(path.join(__dirname, "../build")));

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    otp: { type: String, required: false },
    otpExpiresAt: { type: Date, required: false },
    isVerified: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

const contactUsSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true },
    company: { type: String, required: true },
    message: { type: String, required: true },
  },
  { timestamps: true }
);

const Contactus = mongoose.model("Contactus", contactUsSchema);

// Signup
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Name, email, and password are required." });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpiresAt,
    });

    await newUser.save();

    // Send OTP email
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: process.env.EMAIL,
      to: email,
      subject: "Your OTP for Signup Verification",
      text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
    });

    jwt.sign(
      { email: newUser.email, id: newUser._id },
      process.env.JWT_SECRET,
      {},
      (err, tokenneurophi) => {
        if (err) {
          console.error(err);
          return res.status(500).json("Failed to generate tokenneurophi");
        }
        res
          .cookie("neurophilogin", tokenneurophi, {
            httpOnly: true,
            secure: true, // used in production ready projects as they have https but localhost runs on http
            sameSite: "none", // Allow cross-origin cookies
          })
          .status(200)
          .json({
            message: "Signup successful! OTP sent to your email",
          });

        console.log("cookie should work");
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "An error occurred during signup." });
  }
});

// Verify OTP Route
app.post("/api/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: "User is already verified." });
    }

    if (user.otp !== otp || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ error: "Invalid or expired OTP." });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    res.status(200).json({
      message: "OTP verified successfully! Your account is now active.",
    });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ error: "An error occurred during OTP verification." });
  }
});

// Login
app.post("/api/login", cors(), async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    jwt.sign(
      { email: user.email, id: user._id },
      process.env.JWT_SECRET,
      {},
      (err, tokenneurophi) => {
        if (err) {
          console.error(err);
          return res.status(500).json("Failed to generate tokenneurophi");
        }
        res
          .cookie("neurophilogin", tokenneurophi, {
            httpOnly: true,
            secure: true, // used in production ready projects as they have https but localhost runs on http
            sameSite: "none", // Allow cross-origin cookies
          })
          .status(200)
          .json({
            message: "Login successful",
          });

        console.log("cookie should work");
      }
    );
  } catch (err) {
    next(err);
  }
});

// Contact
app.post("/api/contact", async (req, res, next) => {
  try {
    const { name, email, company, message } = req.body;

    if (!name || !email || !company || !message) {
      return res.status(400).json({ error: "Email and message are required" });
    }

    const newMessage = new Contactus({ name, email, company, message });
    await newMessage.save();

    res.status(201).json({ message: "Message sent successfully" });
  } catch (err) {
    next(err);
  }
});

// Send OTP
app.post("/api/sendotp", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await user.save();

    // Send email
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: process.env.EMAIL,
      to: email,
      subject: "Your OTP for Password Reset",
      text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
    });

    res.status(200).json({ message: "OTP sent to your email" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

app.post("/api/resetpassword", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.otp !== otp || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

app.post("/api/islogin", async (req, res) => {
  const { neurophilogin } = req.cookies;
  if (!neurophilogin) return res.status(401).json("something went wrong");
  jwt.verify(neurophilogin, process.env.JWT_SECRET, (err, info) => {
    if (err) {
      console.error("tokensocin verification error:", err);
      return res.status(401).json("Invalid tokensocin");
    }
    res.json(info);
  });
});

app.post("/api/logout", (req, res) => {
  res.cookie("neurophilogin", "").json("Logged out");
});

app.get('/api/test', (req, res) => {
    const origin = req.headers.origin || "unknown origin";
    res.status(200).send(`Backend is working! Request origin: ${origin}`);
});


// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../build/index.html"));
});

// Your error handler and port configuration remain the same
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://neurophi.tech"); // Set your frontend domain
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

app.options('*', cors({
  origin: 'https://neurophi.tech',
  credentials: true,
}));


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
