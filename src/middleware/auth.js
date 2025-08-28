import jwt from "jsonwebtoken";

const SECRET = "supersecretkey"; // use ENV in production

export const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect("/login");
  }
};

export const roleMiddleware = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).send("Forbidden: Insufficient rights");
    }
    next();
  };
};
