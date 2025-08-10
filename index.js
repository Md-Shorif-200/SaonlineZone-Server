const express = require('express');
const cors = require('cors');
const app = express();
const cookieParser = require('cookie-parser');
const port = process.env.PORT || 5000;
require('dotenv').config()
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb'); // ObjectId import করুন
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { authenticateToken, authorizeRole } = require('./middleware/auth');



// middlewares 
app.use(express.json())
app.use(cookieParser())

// CORS configuration ঠিক করুন
app.use(cors({
    origin: [
        'http://localhost:5173', 
        'http://localhost:3000',
        // 'https://your-frontend-domain.vercel.app', // আপনার actual frontend domain দিন
        // development এর জন্য
        process.env.CLIENT_URL || 'http://localhost:5173'
    ], 
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization']
}))
// !mongodb uri link

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.56yvv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // await client.connect();

    // Database collection
    const db = client.db('SaonlineZone-Db');
    const usersCollection = db.collection('All-Users');

    // JWT token তৈরি করার function
    const generateToken = (userId, email, role) => {
        return jwt.sign(
            { userId, email, role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' } // 7 দিনের জন্য valid
        );
    };

 // Login route এ cookie settings ঠিক করুন
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        if (user.password !== password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        const token = generateToken(user._id, user.email, user.role);

        // Cookie settings ঠিক করুন
        res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Production এ true
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Cross-origin এর জন্য
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 দিন
            path: '/' // Cookie path specify করুন
        });

        const { password: userPassword, ...userWithoutPassword } = user;
        
        res.json({
            success: true,
            message: 'Login successful',
            user: userWithoutPassword
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login' 
        });
    }
});

// Logout route ঠিক করুন
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('authToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        path: '/'
    });
    res.json({ 
        success: true, 
        message: 'Logged out successfully' 
    });
});

    // Current user profile route (authentication required)
    app.get('/api/auth/me', authenticateToken(usersCollection), (req, res) => {
        res.json({
            success: true,
            user: req.user
        });
    });

    // আপনার existing user registration route (role field যোগ করা হয়েছে)
    app.post('/api/all-users', async (req, res) => {
        try {
            const user = req.body;
            const query = { email: user.email };
            
            // User already exists check
            const userAlreadyExist = await usersCollection.findOne(query);
            if (userAlreadyExist) {
                return res.send({
                    success: false,
                    message: 'You are already signed up. Please sign in',
                    insertedId: null
                });
            }

            // Default role 'user' set করুন যদি না থাকে
            if (!user.role) {
                user.role = 'user';
            }

            // Password hash করুন (production এ)
            // if (user.password) {
            //     user.password = await bcrypt.hash(user.password, 10);
            // }

            const result = await usersCollection.insertOne(user);
            res.send({
                success: true,
                message: 'User created successfully',
                insertedId: result.insertedId
            });

        } catch (error) {
            console.error('User creation error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Server error during user creation' 
            });
        }
    });

    // Protected route - সব authenticated user access করতে পারবে
    app.get('/api/all-users', 
        authenticateToken(usersCollection), 
        async (req, res) => {
            try {
                // শুধু admin রা সব user দেখতে পারবে
                if (req.user.role !== 'admin') {
                    return res.status(403).json({
                        success: false,
                        message: 'Only admins can view all users'
                    });
                }

                const result = await usersCollection
                    .find({}, { projection: { password: 0 } }) // password বাদ দিয়ে
                    .toArray();
                
                res.json({
                    success: true,
                    users: result,
                    count: result.length
                });

            } catch (error) {
                console.error('Error fetching users:', error);
                res.status(500).json({ 
                    success: false, 
                    message: 'Server error' 
                });
            }
        }
    );

    // Admin only route - user role update করার জন্য
    app.patch('/api/admin/users/:id/role', 
        authenticateToken(usersCollection),
        authorizeRole(['admin']),
        async (req, res) => {
            try {
                const { id } = req.params;
                const { role } = req.body;

                // Valid roles check
                const validRoles = ['user', 'admin'];
                if (!validRoles.includes(role)) {
                    return res.status(400).json({
                        success: false,
                        message: 'Invalid role. Must be user or admin'
                    });
                }

                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role, updatedAt: new Date() } }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: 'User not found'
                    });
                }

                res.json({
                    success: true,
                    message: 'User role updated successfully'
                });

            } catch (error) {
                console.error('Role update error:', error);
                res.status(500).json({ 
                    success: false, 
                    message: 'Server error' 
                });
            }
        }
    );

    // Admin only route - user delete
    app.delete('/api/admin/users/:id', 
        authenticateToken(usersCollection),
        authorizeRole(['admin']),
        async (req, res) => {
            try {
                const { id } = req.params;

                // নিজেকে delete করতে পারবে না
                if (req.user._id.toString() === id) {
                    return res.status(400).json({
                        success: false,
                        message: 'You cannot delete your own account'
                    });
                }

                const result = await usersCollection.deleteOne({ 
                    _id: new ObjectId(id) 
                });

                if (result.deletedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: 'User not found'
                    });
                }

                res.json({
                    success: true,
                    message: 'User deleted successfully'
                });

            } catch (error) {
                console.error('User deletion error:', error);
                res.status(500).json({ 
                    success: false, 
                    message: 'Server error' 
                });
            }
        }
    );

    // User statistics (Admin only)
    // app.get('/api/admin/stats', 
    //     authenticateToken(usersCollection),
    //     authorizeRole(['admin']),
    //     async (req, res) => {
    //         try {
    //             const totalUsers = await usersCollection.countDocuments();
    //             const adminCount = await usersCollection.countDocuments({ role: 'admin' });
    //             const userCount = await usersCollection.countDocuments({ role: 'user' });

    //             res.json({
    //                 success: true,
    //                 stats: {
    //                     totalUsers,
    //                     adminCount,
    //                     userCount,
    //                     generatedAt: new Date()
    //                 }
    //             });

    //         } catch (error) {
    //             console.error('Stats error:', error);
    //             res.status(500).json({ 
    //                 success: false, 
    //                 message: 'Server error' 
    //             });
    //         }
    //     }
    // );

    // বাকি আপনার existing code...

    // await client.db("admin").command({ ping: 1 });
    // console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);





app.get('/', (req,res) => {
    res.send('saonlinezone is running')
})

app.listen(port, () => {
     console.log('saonlinezone is running on port', port);
     
})