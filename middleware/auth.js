// middleware/auth.js ফাইল তৈরি করুন
const jwt = require('jsonwebtoken');
const { ObjectId } = require('mongodb');

// JWT token verify করার middleware
const authenticateToken = (usersCollection) => {
    return async (req, res, next) => {
        try {
            const token = req.cookies.authToken; // HTTP-only cookie থেকে token নিন

            if (!token) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Access token required' 
                });
            }

            // Token verify করুন
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Database থেকে user খুঁজুন
            const user = await usersCollection.findOne({ 
                _id: new ObjectId(decoded.userId) 
            });

            if (!user) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid token' 
                });
            }

            // Password বাদ দিয়ে user info req.user এ সেট করুন
            const { password, ...userWithoutPassword } = user;
            req.user = userWithoutPassword;
            
            next();
        } catch (error) {
            console.error('Token verification error:', error);
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
    };
};

// Role check করার middleware
const authorizeRole = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Unauthorized access' 
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Insufficient permissions',
                userRole: req.user.role,
                requiredRoles: allowedRoles
            });
        }

        next();
    };
};

module.exports = { authenticateToken, authorizeRole };