import jsonwebtoken from "jsonwebtoken";

const authMiddleware = (req, res, next) => {
  try {
    const bearerToken = req.headers.authorization;
    if (!bearerToken) {
      throw new Error("Unauthorized. Missing auth token.");
    }
    const jwt = bearerToken.slice(7, bearerToken.length);
    const decoded = jsonwebtoken.verify(jwt, process.env.JWT_SECRET);
    req.userId = decoded._id;
    next();
  } catch (err) {
    console.error(err);
    res.status(401);
    res.json({ error: err.message });
  }
};

export default authMiddleware;

// ------------ Example auth middleware for other services ------------
// 
// const authMiddleware = async (req, res, next) => {
//   try {
//     const bearerToken = req.headers.authorization;
//     if (!bearerToken) {
//       throw new Error("Unauthorized. Missing auth token.");
//     }
//     const jwt = bearerToken.slice(7, bearerToken.length);
//     const url = `${AUTH_SERVICE_API}/verify`;
//     const verify = await getRequest(url, jwt);
//     if (!verify.verified) {
//       throw new Error("Invalid token.");
//     }
//     next();
//   } catch (err) {
//     console.error(err);
//     res.status(404);
//     res.json({ error: err.message });
//   }
// };