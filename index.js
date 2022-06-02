import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import jsonwebtoken from "jsonwebtoken";
import bcrypt from "bcrypt";
import { MongoClient } from "mongodb";
import "dotenv/config";
import authMiddleware from "./middleware/authMiddleware.js";

const uri = "mongodb://mongo:27017";
const port = 8080;
const saltRounds = 10;

const app = express();
const mongoClient = await MongoClient.connect(uri);
const db = mongoClient.db("user");

app.use(bodyParser.json());
app.use(cors());

const jwtSign = (id) => {
  return jsonwebtoken.sign(
    {
      _id: id,
    },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );
};

app.get("/ping", (req, res) => {
  res.json("pong");
});

app.get("/user", authMiddleware, async (req, res) => {
  const { userId } = req;
  try {
    const foundUser = await db.collection("users").findOne({}, { _id: userId });
    delete foundUser.password;
    res.json(foundUser);
  } catch (err) {
    console.error(err);
    res.status(400);
    res.json({ message: "Invalid token." });
  }
});

app.post("/user", async (req, res) => {
  const user = req.body;
  try {
    const foundUser = await db
      .collection("users")
      .findOne({ email: user.email });
    if (foundUser) {
      throw new Error("Email already in use.");
    }
    user.password = await bcrypt.hash(user.password, saltRounds);
    const insertedUser = await db.collection("users").insertOne(user);
    const jwt = jwtSign(insertedUser.insertedId);
    delete user.password;
    res.json({ user, jwt });
  } catch (err) {
    console.error(err);
    res.status(400);
    res.json({ error: err.message });
  }
});

app.post("/login", async (req, res) => {
  const user = req.body;
  try {
    const foundUser = await db
      .collection("users")
      .findOne({ email: user.email });
    if (!foundUser) {
      throw new Error("User not found. Please register first");
    }
    const validPassword = await bcrypt.compare(
      user.password,
      foundUser.password
    );
    if (!validPassword) {
      throw new Error("Wrong password.");
    }
    const jwt = jwtSign(foundUser._id);
    delete user.password;
    res.json({ jwt });
  } catch (err) {
    console.error(err);
    res.status(400);
    res.json({ message: err.message });
  }
});

app.get("/verify", authMiddleware, async (req, res) => {
  res.json({ verified: true });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

// docker build . -t notification-service
// docker compose up -d

// [x] /user POST route
// [x] /login POST route
// [x] /verify route
// [x] /user GET route
// [x] authMiddleware
// [ ] email, password validation
// [ ] forgot password
// [ ] passwordless login, email me a code
// [ ] redis blacklists
// [ ] sigin with google
// [ ] set cors to accept specific sites
// [ ] try to implement some way to check if user logged out from other device (ip) then blacklist that token
