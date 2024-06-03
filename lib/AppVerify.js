const jwt = require("jsonwebtoken");

const AppVerify = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    console.log(req.headers);
    if (!authHeader) {
      return res.status(401).json({ message: "Authorization header missing" });
    }

    const token = authHeader.split(" ")[1];
    console.log("Token:", token);
    if (!token) {
      return res.status(401).json({ message: "Token missing or invalid" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res
      .status(401)
      .json({ message: "You are not Authorized", error: err.message });
  }
};

module.exports = AppVerify;
