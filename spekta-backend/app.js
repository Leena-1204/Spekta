import express from 'express';
import cors from 'cors';
import { DynamoDB, DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, ScanCommand, UpdateCommand, BatchGetCommand, GetCommand , DeleteCommand , QueryCommand} from '@aws-sdk/lib-dynamodb';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import multer from 'multer';
import { google } from 'googleapis';
import { fileURLToPath } from 'url';
import fs from 'node:fs';
import path from 'node:path';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import CryptoJS from 'crypto-js';

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const port = 5001;

const CLIENT_ID = process.env.G_CLIENT_ID;
const CLIENT_SECRET = process.env.G_CLIENT_SECRET;
const REDIRECT_URI = process.env.G_REDIRECT_URI;
const REFRESH_TOKEN = process.env.G_REFRESH_TOKEN;

const G_DRIVE_PROFILE_FOLDER_ID = '1uiF24eSUD7jTjk6CuEEvYiMFwmCptU0g';
const G_DRIVE_POSTS_FOLDER_ID = '1lN_WfJlwqETwh6idKj_mqTHDYrhpHXj9';

const oauth2client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
oauth2client.setCredentials({ refresh_token: REFRESH_TOKEN });

const drive = google.drive({ version: 'v3', auth: oauth2client });

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
    maxAttempts: 3,
});

const dynamoDB = DynamoDBDocumentClient.from(client);

const testDynamoDBConnection = async () => {
    try {
        const params = { TableName: 'user_details', Limit: 1 };
        await dynamoDB.send(new ScanCommand(params));
        console.log('Database connection is ready.');
        return true;
    } catch (error) {
        console.error('Database connection error:', error);
        return false;
    }
};

app.use(cors());
app.use(express.json());

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error', message: err.message });
});

const generateRandomPin = () => {
    return Math.floor(100000 + Math.random() * 900000);
};

const hashOtp = async (otp) => {
    const saltRounds = 10;
    const hashedOtp = await bcrypt.hash(otp.toString(), saltRounds);
    return hashedOtp;
};

const sendOtpEmail = async (userEmail) => {
    const pin = generateRandomPin();
    const otpExpiry = Date.now() + 10 * 60 * 1000;

    const hashedOtp = await hashOtp(pin);

    const params = {
        TableName: 'otp_table',
        Item: {
            email: userEmail,
            otp: hashedOtp,
            expiry: otpExpiry.toString(),
        }
    };

    try {
        await dynamoDB.send(new PutCommand(params));
        console.log('OTP stored successfully in DynamoDB');

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'spekta1222@gmail.com',
                pass: process.env.EMAIL_PASSWORD,
            },
        });

        const mailOptions = {
            from: 'spekta1222@gmail.com',
            to: userEmail,
            subject: 'Verify Spekta Account',
            html: `
                <div style="font-family: Arial, sans-serif; color: #333;">
                    <div style="text-align: center; padding: 20px; background-color: #f4f4f4; border-radius: 8px;">
                        <h2 style="color: #189D0E;">Your OTP Code</h2>
                        <p style="font-size: 18px;">Please use the following one-time passcode (OTP) to complete your verification process.</p>
                        <h1 style="font-size: 36px; font-weight: bold; color: #189D0E;">${pin}</h1>
                        <p style="font-size: 16px; color: #555;">This code will expire in 10 minutes. Please use it promptly.</p>
                        <hr style="border: 1px solid #ddd; margin: 20px 0;" />
                        <p style="font-size: 14px; color: #777;">If you did not request this OTP, please ignore this email.</p>
                    </div>
                </div>
            `,
        };

        await transporter.sendMail(mailOptions);
        console.log('OTP email sent successfully');
    } catch (error) {
        console.error('Error sending OTP:', error);
        throw new Error('Failed to send OTP');
    }
};

function sendToUser(userId, message) {
    const userConnection = connections.get(userId);
    if (userConnection && userConnection.readyState === 1) { // Check if connection is open
        userConnection.send(JSON.stringify(message));
    }
}

app.post('/register', async (req, res) => {
    const { username, fullname, email, number, password, deviceName } = req.body;

    const normalizedUsername = username.toLowerCase();
    const normalizedEmail = email.toLowerCase();

    if (!normalizedUsername || !fullname || !normalizedEmail || !number || !password) {
        return res.status(400).json({ error: 'Validation failed', details: 'All fields are required.' });
    }

    try {
        const params = {
            TableName: 'user_details',
            FilterExpression: 'username = :username OR email = :email',
            ExpressionAttributeValues: {
                ':username': normalizedUsername,
                ':email': normalizedEmail,
            }
        };

        const existingUser = await dynamoDB.send(new ScanCommand(params));

        if (existingUser.Items && existingUser.Items.length > 0) {
            return res.status(409).json({ error: 'Registration failed', details: 'Username or email already exists' });
        }

        const userId = uuidv4().replace(/-/g, '');

        const newUser = {
            userId: userId,
            username: normalizedUsername,
            fullname: fullname,
            email: normalizedEmail,
            number: number,
            password: await bcrypt.hash(password, 10),
            deviceName: deviceName,
            joinedDate: new Date().toISOString(),
            loginDate: null,
            followers: 0,
            following: 0,
            profileUrl: null,
            isAdmin: false,
            is2FAEnabled: false
        };

        await dynamoDB.send(new PutCommand({
            TableName: 'user_details',
            Item: newUser,
        }));

        await sendOtpEmail(normalizedEmail);

        res.status(200).json({ message: 'User registered successfully! Please verify your email using the OTP.' });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed', details: error.message });
    }
});


app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ error: 'Email and OTP are required' });
    }

    try {
        const getParams = {
            TableName: 'otp_table',
            Key: { email },
        };

        const otpData = await dynamoDB.send(new GetCommand(getParams));

        if (!otpData.Item) {
            return res.status(400).json({ error: 'No OTP found for this email. Please request a new OTP.' });
        }

        const storedOtp = otpData.Item.otp;
        const expiryTime = parseInt(otpData.Item.expiry, 10);

        if (Date.now() > expiryTime) {
            return res.status(400).json({ error: 'OTP has expired, please request a new one' });
        }

        const isOtpValid = await bcrypt.compare(otp, storedOtp);

        if (isOtpValid) {
            return res.status(200).json({ success: true });
        } else {
            return res.status(400).json({ error: 'Invalid OTP' });
        }
    } catch (error) {
        console.error('Error verifying OTP:', error);
        return res.status(500).json({ error: 'Error verifying OTP', details: error.message });
    }
});


app.post('/login', async (req, res) => {
    const { username, password, deviceName } = req.body;

    const normalizedUsername = username.toLowerCase();

    if (!normalizedUsername || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const params = {
            TableName: 'user_details',
            FilterExpression: 'username = :username OR email = :email',
            ExpressionAttributeValues: { ':username': normalizedUsername, ':email': normalizedUsername }
        };

        const result = await dynamoDB.send(new ScanCommand(params));
        const user = result.Items?.find(item => 
            item.username === normalizedUsername || item.email === normalizedUsername
        );

        if (!user) {
            return res.status(401).json({ error: 'Authentication failed', details: 'User not found' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Authentication failed', details: 'Invalid password' });
        }

        await dynamoDB.send(new UpdateCommand({
            TableName: 'user_details',
            Key: { userId: user.userId },
            UpdateExpression: 'SET deviceName = :deviceName, loginDate = :loginDate',
            ExpressionAttributeValues: { ':deviceName': deviceName, ':loginDate': new Date().toISOString() }
        }));

        const userData = { 
            username: user.username, 
            fullname: user.fullname, 
            email: user.email, 
            number: user.number, 
            _id: user.userId,
            profileUrl: user.profileUrl || '',
            is2FAEnabled: user.is2FAEnabled || false,
            isAdmin: user.isAdmin || false
        };
        
        res.status(200).json({ message: 'Login successful', user: userData });
        if(userData.is2FAEnabled){
            await sendOtpEmail(userData.email);
        }
    } catch (error) {
        console.error('Login error occurred:', error);
        res.status(500).json({ error: 'Login failed', details: error.message });
    }
});


const uploadDir = 'uploads/profilepics/';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true }); 
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir); 
    },
    filename: (req, file, cb) => {
        const userId = file.originalname.split('.')[0]; 
        const fileExt = path.extname(file.originalname) || '.png'; 
        cb(null, `${userId}${fileExt}`); 
    }
});

const upload = multer({ storage });

app.post('/uploadprofilepic', upload.single('image'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No File Uploaded' });
    }

    const userId = req.file.filename.split('.')[0]; 
    const filePath = path.join(__dirname, 'uploads/profilepics', req.file.filename);

    try {
        const response = await drive.files.create({
            requestBody: {
                name: req.file.filename,
                mimeType: 'image/png',
                parents: [G_DRIVE_PROFILE_FOLDER_ID],
            },
            media: {
                mimeType: 'image/png',
                body: fs.createReadStream(filePath),
            }
        });

        const fileId = response.data.id;
        const driveUrl = `https://drive.google.com/uc?id=${fileId}`;

        await dynamoDB.send(new UpdateCommand({
            TableName: 'user_details',
            Key: { userId },
            UpdateExpression: 'SET profileUrl = :profileUrl',
            ExpressionAttributeValues: { ':profileUrl': driveUrl }
        }));

        res.json({
            message: 'File Uploaded Successfully',
            driveFileId: fileId,
            driveFileUrl: driveUrl
        });

        fs.unlink(filePath, (err) => {
            if (err) {
                console.error('Error deleting local file:', err);
            }
        });

    } catch (error) {
        console.error('Google Drive Upload Error:', error.message);
        return res.status(500).json({ message: 'Failed to upload to Google Drive', error: error.message });
    }
});

app.put('/updateprofile', async (req, res) => {
    const { userId, fullname, email, number, bio, is2FAEnabled } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'userId is required' });
    }

    if (!fullname && !email && !number && !bio && is2FAEnabled === undefined) {
        return res.status(400).json({ error: 'At least one field (fullname, email, number, bio, or is2FAEnabled) must be provided' });
    }

    if (bio && bio.length > 100) {
        return res.status(400).json({ error: 'Bio must not exceed 100 characters' });
    }

    try {
        const { Item } = await dynamoDB.send(new GetCommand({
            TableName: 'user_details',
            Key: { userId }
        }));

        if (!Item) {
            return res.status(404).json({ error: 'User not found' });
        }

        const updateExpressions = [];
        const expressionAttributeValues = {};
        const expressionAttributeNames = {};

        // Only update if the new values are different from the existing ones
        if (fullname && fullname !== Item.fullname) {
            updateExpressions.push('#fullname = :fullname');
            expressionAttributeValues[':fullname'] = fullname;
            expressionAttributeNames['#fullname'] = 'fullname';
        }

        if (email && email !== Item.email) {
            updateExpressions.push('#email = :email');
            expressionAttributeValues[':email'] = email;
            expressionAttributeNames['#email'] = 'email';
        }

        if (number && number !== Item.number) {
            updateExpressions.push('#number = :number');
            expressionAttributeValues[':number'] = number;
            expressionAttributeNames['#number'] = 'number';
        }

        if (bio && bio !== Item.bio) {
            updateExpressions.push('#bio = :bio');
            expressionAttributeValues[':bio'] = bio;
            expressionAttributeNames['#bio'] = 'bio';
        }

        // Check for changes in the 2FA setting and add it to the update expression if needed
        if (is2FAEnabled !== undefined && is2FAEnabled !== Item.is2FAEnabled) {
            updateExpressions.push('#is2FAEnabled = :is2FAEnabled');
            expressionAttributeValues[':is2FAEnabled'] = is2FAEnabled;
            expressionAttributeNames['#is2FAEnabled'] = 'is2FAEnabled';
        }

        if (updateExpressions.length === 0) {
            return res.status(400).json({ error: 'No changes detected to update' });
        }

        const updateExpression = `SET ${updateExpressions.join(', ')}`;

        await dynamoDB.send(new UpdateCommand({
            TableName: 'user_details',
            Key: { userId },
            UpdateExpression: updateExpression,
            ExpressionAttributeNames: expressionAttributeNames,
            ExpressionAttributeValues: expressionAttributeValues
        }));

        res.status(200).json({
            message: 'Profile updated successfully',
            user: {
                userId: Item.userId,
                fullname: fullname || Item.fullname,
                email: email || Item.email,
                number: number || Item.number,
                bio: bio || Item.bio,
                is2FAEnabled: is2FAEnabled !== undefined ? is2FAEnabled : Item.is2FAEnabled
            }
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Profile update failed', details: error.message });
    }
});

app.get('/getprofilepic', async (req, res) => {
    const { userId } = req.query;

    try {
        const { Item } = await dynamoDB.send(new GetCommand({
            TableName: 'user_details',
            Key: { userId }
        }));

        if (!Item || !Item.profileUrl) {
            return res.status(404).json({ message: 'Profile picture not found' });
        }

        res.json({ profileUrl: Item.profileUrl });
    } catch (error) {
        console.error("Error fetching profile picture:", error);
        res.status(500).json({ message: "Error fetching profile picture", error: error.message });
    }
});

// Delete profile picture
app.delete('/deleteprofilepic', async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({
                message: 'userId is required'
            });
        }

        const userResult = await dynamoDB.send(new GetCommand({
            TableName: 'user_details',
            Key: {
                userId: userId.toString() // Ensure userId is a string
            }
        }));

        if (!userResult.Item) {
            return res.status(404).json({
                message: 'User  not found'
            });
        }

        if (!userResult.Item.profileUrl) {
            return res.status(404).json({
                message: 'No profile picture found for this user'
            });
        }

        // Extract file ID from Google Drive URL
        const imageFileId = userResult.Item.profileUrl.split('id=')[1];

        try {
            // Delete file from Google Drive
            await drive.files.delete({
                fileId: imageFileId
            });
        } catch (driveError) {
            console.error('Google Drive deletion error:', driveError);
            // Continue with DB update even if Drive deletion fails
        }

        // Remove profileUrl from DynamoDB
        await dynamoDB.send(new UpdateCommand({
            TableName: 'user_details',
            Key: {
                userId: userId.toString() // Ensure userId is a string
            },
            UpdateExpression: 'REMOVE profileUrl',
        }));

        res.status(200).json({
            message: 'Profile picture deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting profile picture:', error);
        
        if (error.name === 'Validation Exception') {
            return res.status( 400).json({
                message: 'Invalid userId format',
                error: error.message
            });
        }

        res.status(500).json({
            message: 'Failed to delete profile picture',
            error: error.message
        });
    }
});

app.get('/getuserdata', async (req, res) => {
    try {
        const params = {
            TableName: 'user_details',
            Limit: 100
        };
        const result = await dynamoDB.send(new ScanCommand(params));

        const sanitizedUsers = result.Items.map(user => ({
            userId: user.userId,
            username: user.username,
            fullname: user.fullname,
            email: user.email,
            bio : user.bio,
            profileUrl: user.profileUrl || '',
            followers: user.followers || 0,
            following: user.following || 0
        }));

        res.json({ users: sanitizedUsers });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/', async (req, res) => {
    const { userId } = req.query;

    if (!userId || typeof userId !== 'string') {
        return res.status(400).json({ error: 'UserId query parameter is required and must be a string' });
    }

    try {
        const { Item } = await dynamoDB.send(new GetCommand({
            TableName: 'user_details',
            Key: { userId }
        }));

        if (!Item) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ username: Item.username, profileUrl: Item.profileUrl, bio: Item.bio, followers: Item.followers, following: Item.following });
    } catch (error) {
        console.error("Error fetching user data:", error);
        res.status(500).json({ message: "Error fetching user data", error: error.message });
    }
});

app.get('/search', async (req, res) => {
    const { query } = req.query;

    if (!query) {
        return res.status(400).json({ error: 'Search query is required' });
    }

    try {
        const normalizedQuery = query.toLowerCase();

        const userParams = {
            TableName: 'user_details',
            FilterExpression: 
                'contains(#username, :query) OR ' +
                'contains(#fullname, :query)',
            ExpressionAttributeNames: {
                '#username': 'username',
                '#fullname': 'fullname',
            },
            ExpressionAttributeValues: {
                ':query': normalizedQuery
            }
        };

        const userResult = await dynamoDB.send(new ScanCommand(userParams));
        
        const userResults = userResult.Items.map(user => ({
            type: 'user',
            userId: user.userId,
            username: user.username,
            fullname: user.fullname,
            profileUrl: user.profileUrl || ''
        }));

        const postParams = {
            TableName: 'posts',
            FilterExpression: 
                'contains(#content, :query) OR ' +
                'contains(#hashtags, :query) OR ' +
                'contains(#location, :query)',
            ExpressionAttributeNames: {
                '#content': 'content',
                '#hashtags': 'hashtags',
                '#location': 'location'
            },
            ExpressionAttributeValues: {
                ':query': normalizedQuery
            }
        };

        const postResult = await dynamoDB.send(new ScanCommand(postParams));
        
        const postResults = postResult.Items.map(post => ({
            type: 'post',
            postId: post.postId,
            userId: post.userId,
            content: post.content,
        }));

        const combinedResults = [...userResults, ...postResults];
  
        res.status(200).json(combinedResults);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed', details: error.message });
    }
});

app.get('/users', async (req, res) => {
    try {
        const params = { TableName: 'user_details' };
        const result = await dynamoDB.send(new ScanCommand(params));
        
        res.status(200).json(result.Items);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Could not fetch users.' });
    }
});

app.get('/posts', async (req, res) => {
    try {
        const platform = req.query.platform;
        const params = { TableName: 'posts' };
        const result = await dynamoDB.send(new ScanCommand(params));

        const posts = result.Items;

        const postsWithUserDetails = await Promise.all(posts.map(async (post) => {
            try {
                const { Item: user } = await dynamoDB.send(new GetCommand({
                    TableName: 'user_details',
                    Key: { userId: post.userId }
                }));

                let mediaUrl = post.mediaUrl;
                let googleDriveFileId= post.googleDriveFileId; 

                return {
                    ...post,
                    username: user?.username || 'Unknown User',
                    profileUrl: user?.profileUrl || '',
                    fullname: user?.fullname || '',
                };
            } 
            catch (error) {
                console.error(`Error fetching user for post ${post.postId}:, error`);
                return post;
            }
        }));

        res.status(200).json(postsWithUserDetails);
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ error: 'Failed to fetch posts.' });
    }
});

app.get('/getuserposts', async (req, res) => {
    const { userId } = req.query;

    if (!userId) {
        return res.status(400).json({ error: 'UserId query parameter is required' });
    }

    try {
        const params = { TableName: 'posts' };
        const result = await dynamoDB.send(new ScanCommand(params));

        const userPosts = result.Items.filter(post => post.userId === userId);

        const postsWithUserDetails = await Promise.all(userPosts.map(async (post) => {
            try {
                const { Item: user } = await dynamoDB.send(new GetCommand({
                    TableName: 'user_details',
                    Key: { userId: post.userId }
                }));

                return {
                    ...post,
                    username: user?.username || 'Unknown User',
                    profileUrl: user?.profileUrl || '',
                    fullname: user?.fullname || ''
                };
            } catch (error) {
                console.error(`Error fetching user for post ${post.postId}:`, error);
                return post;
            }
        }));

        res.status(200).json({ posts: postsWithUserDetails });
    } catch (error) {
        console.error('Error fetching user posts:', error);
        res.status(500).json({ error: 'Failed to fetch user posts.' });
    }
});


const startServer = async () => {
    try {
        const dbConnected = await testDynamoDBConnection();
        
        if (!dbConnected) {
            console.error('Failed to connect to database. Exiting...');
            process.exit(1);
        }

        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
        
    } catch (error) {
       console.error('Failed to start server:', error);
       process.exit(1);
   }
};

const postsStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(process.cwd(), 'uploads/posts');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, 'post-' + uniqueSuffix + ext);
    }
});

const postsUpload = multer({
    storage: postsStorage,
    limits: {
        fileSize: 10 * 1024 * 1024, 
    },
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only image files (jpg, jpeg, png, gif) are allowed!'));
    }
}).single('media');

const handleUpload = (req, res) => {
    return new Promise((resolve, reject) => {
        postsUpload(req, res, function (err) {
            if (err instanceof multer.MulterError) {
                reject({ status: 400, message: 'File upload error: ' + err.message });
            } else if (err) {
                reject({ status: 500, message: err.message });
            }
            resolve();
        });
    });
};

app.post('/createposts', async (req, res) => {
    try {
        await handleUpload(req, res);

        const { content, location, mentions, hashtags, userId } = req.body;

        if (!content && !req.file) {
            return res.status(400).json({ error: 'Either content or media is required' });
        }

        const postId = `p${uuidv4().replace(/-/g, '')}`;
        let mediaUrl = '';
        let googleDriveFileId = null; // Store the fileId

        if (req.file) {
            try {
                const response = await drive.files.create({
                    requestBody: {
                        name: req.file.filename,
                        mimeType: req.file.mimetype,
                        parents: [G_DRIVE_POSTS_FOLDER_ID],
                    },
                    media: {
                        mimeType: req.file.mimetype,
                        body: fs.createReadStream(req.file.path),
                    }
                });

                mediaUrl = `https://drive.google.com/uc?id=${response.data.id}`;
                googleDriveFileId = response.data.id; // Store the fileId
            } catch (error) {
                throw new Error('Failed to upload media to Google Drive: ' + error.message);
            } finally {
                if (req.file && req.file.path && fs.existsSync(req.file.path)) {
                    fs.unlinkSync(req.file.path);
                }
            }
        }

        const parsedMentions = mentions ? JSON.parse(mentions) : [];
        const parsedHashtags = hashtags ? JSON.parse(hashtags) : [];

        const postData = {
            postId,
            userId,
            content: content || '',
            location: location || '',
            mentions: parsedMentions,
            hashtags: parsedHashtags,
            mediaUrl,
            googleDriveFileId, // Store the fileId in DynamoDB
            createdAt: new Date().toISOString(),
        };

        await dynamoDB.send(new PutCommand({
            TableName: 'posts',
            Item: postData
        }));

        res.status(201).json({
            message: 'Post created successfully',
            post: postData
        });

    } catch (error) {
        console.error('Error creating post:', error);
        res.status(error.status || 500).json({ error: error.message || 'Failed to create post' });
    }
});

app.delete('/deletepost',async (req,res) => {
    const {postId,userId} = req.body;

    if(!postId || !userId){
        res.status(500).json({message:'Missing Args'});
    }
    try {
        const postRes = await dynamoDB.send(new ScanCommand({
            TableName: 'posts',
            FilterExpression: 'postId = :postId AND userId = :userId',
            ExpressionAttributeValues: {
                ':postId': postId,
                ':userId': userId
            }
        }));

        if (postRes.Items.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }

        await dynamoDB.send(new DeleteCommand({
            TableName: 'posts',
            Key: { postId }
        }));

        res.status(200).json({ message: 'Post removed successfully' });
    } catch (error) {
        console.error('Error removing like:', error);
        res.status(500).json({ error: 'Failed to remove like', details: error.message });
    }
    
})

process.on('unhandledRejection', (error) => {
   console.error('Unhandled Rejection:', error);
   process.exit(1);
});

process.on('uncaughtException', (error) => {
   console.error('Uncaught Exception:', error);
   process.exit(1);
});

app.post('/addlike', async (req, res) => {
    const { postId, userId, date } = req.body;

    if (!postId || !userId || !date) {
        return res.status(400).json({ error: 'postId, userId, and date are required' });
    }

    const likesId = uuidv4(); // Generate a unique likesId

    try {
        // Add the like to the likes table
        await dynamoDB.send(new PutCommand({
            TableName: 'likes',
            Item: {
                likesId,  // Unique ID for the like entry
                postId,
                userId,
                date,
            }
        }));

        // Increment the likes count in the posts table
        await dynamoDB.send(new UpdateCommand({
            TableName: 'posts',
            Key: { postId },
            UpdateExpression: 'SET likes = if_not_exists(likes, :zero) + :increment',
            ExpressionAttributeValues: { 
                ':increment': 1,
                ':zero': 0
            }
        }));

        res.status(201).json({ message: 'Like added successfully', likesId });
    } catch (error) {
        console.error('Error adding like:', error);
        res.status(500).json({ error: 'Failed to add like', details: error.message });
    }
});

app.delete('/removelike', async (req, res) => {
    const { postId, userId } = req.body;

    if (!postId || !userId) {
        return res.status(400).json({ error: 'postId and userId are required' });
    }

    try {
        // Use ScanCommand to find the like
        const likeResult = await dynamoDB.send(new ScanCommand({
            TableName: 'likes',
            FilterExpression: 'postId = :postId AND userId = :userId',
            ExpressionAttributeValues: {
                ':postId': postId,
                ':userId': userId
            }
        }));

        if (likeResult.Items.length === 0) {
            return res.status(404).json({ error: 'Like not found' });
        }

        const likesId = likeResult.Items[0].likesId;

        await dynamoDB.send(new DeleteCommand({
            TableName: 'likes',
            Key: { likesId }
        }));

        // Decrement the likes count safely
        await dynamoDB.send(new UpdateCommand({
            TableName: 'posts',
            Key: { postId },
            UpdateExpression: 'SET likes = if_not_exists(likes, :zero) - :decrement',
            ConditionExpression: 'likes > :zero',
            ExpressionAttributeValues: {
                ':decrement': 1,
                ':zero': 0
            }
        }));

        res.status(200).json({ message: 'Like removed successfully' });
    } catch (error) {
        console.error('Error removing like:', error);
        res.status(500).json({ error: 'Failed to remove like', details: error.message });
    }
});

app.get('/checklike', async (req, res) => {
    const { postId, userId } = req.query;

    if (!postId || !userId) {
        return res.status(400).json({ error: 'postId and userId are required' });
    }

    try {
        const likeResult = await dynamoDB.send(new ScanCommand({
            TableName: 'likes',
            FilterExpression: 'postId = :postId AND userId = :userId',
            ExpressionAttributeValues: {
                ':postId': postId,
                ':userId': userId
            }
        }));

        const isLiked = likeResult.Items.length > 0;

        const { Item: post } = await dynamoDB.send(new GetCommand({
            TableName: 'posts',
            Key: { postId }
        }));

        res.json({
            isLiked,
            likeCount: post?.likes || 0
        });
    } catch (error) {
        console.error('Error checking like status:', error);
        res.status(500).json({ error: 'Failed to check like status' });
    }
});


app.post('/reportpost', async (req, res) => {
    console.log('Received report request:', req.body);

    const { postId, reporterId, date, reason } = req.body;

    if (!postId || !date || !reporterId || !reason) {
        return res.status(400).json({ error: 'Cannot request due to unfilled information...' });
    }

    const reportId = uuidv4();

    try {
        await dynamoDB.send(new PutCommand({
            TableName: 'report',
            Item: {
                reportId,
                postId,
                reporterId,
                reason,
                date
            }
        }));

        return res.status(201).json({ message: 'Reported Successfully!' });
    } catch (error) {
        console.log('Error in reporting:', error.message);
        return res.status(500).json({ error: 'Failed to report message' });
    }
});

app.post('/addcomment', async (req, res) => {
    const {postId, userId, content, timestamp} = req.body;
    
    if (!postId || !userId || !content) {
        return res.status(400).json({ 
            error: 'Missing required fields: postId, userId, and content are required' 
        });
    }

    const commentId = `c${uuidv4().replace(/-/g, '')}`;

    try {
        // Add the comment to comments table
        await dynamoDB.send(new PutCommand({
            TableName: 'comments',
            Item: {
                commentId,  // partition key
                postId,    // sort key
                userId,
                content,
                timestamp: timestamp || Date.now(),
                createdAt: Date.now()
            }
        }));

        // Increment comment count in posts table
        await dynamoDB.send(new UpdateCommand({
            TableName: 'posts',
            Key: { postId },
            UpdateExpression: 'SET comments = if_not_exists(comments, :zero) + :increment',
            ExpressionAttributeValues: { 
                ':increment': 1,
                ':zero': 0
            }
        }));

        res.status(200).json({
            success: true,
            message: 'Comment added successfully',
            commentId
        });
    } catch(error) {
        console.error('Error adding comment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add comment',
            error: error.message
        });
    }
});

// Get comments for a post with pagination
app.get('/getcomments', async (req, res) => {
    const { postId, lastEvaluatedKey, limit = 20 } = req.query;
  
    if (!postId) {
        return res.status(400).json({ error: 'PostId is required' });
    }
  
    try {
        const scanParams = {
            TableName: 'comments',
            FilterExpression: 'postId = :postId',
            ExpressionAttributeValues: {
                ':postId': postId
            },
            Limit: parseInt(limit)
        };

        // Add pagination if lastEvaluatedKey is provided
        if (lastEvaluatedKey) {
            try {
                scanParams.ExclusiveStartKey = JSON.parse(lastEvaluatedKey);
            } catch (e) {
                return res.status(400).json({ error: 'Invalid lastEvaluatedKey format' });
            }
        }

        const result = await dynamoDB.send(new ScanCommand(scanParams));
  
        if (!result.Items || result.Items.length === 0) {
            return res.status(200).json({ 
                comments: [],
                lastEvaluatedKey: null,
                hasMore: false
            });
        }
  
        // Get user details for each comment
        const commentsWithUsernames = await Promise.all(result.Items.map(async (comment) => {
            try {
                const userResult = await dynamoDB.send(new GetCommand({
                    TableName: 'user_details',
                    Key: {
                        userId: comment.userId
                    }
                }));

                return {
                    ...comment,
                    username: userResult.Item ? userResult.Item.username : 'Unknown User',
                    profilePic: userResult.Item ? userResult.Item.profileUrl : 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png'
                };
            } catch (error) {
                console.error('Error fetching user details:', error);
                return {
                    ...comment,
                    username: 'Unknown User',
                    profilePic: 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png'
                };
            }
        }));

        // Sort comments by timestamp (newest first)
        commentsWithUsernames.sort((a, b) => b.timestamp - a.timestamp);
  
        return res.status(200).json({ 
            success: true,
            comments: commentsWithUsernames,
            lastEvaluatedKey: result.LastEvaluatedKey ? JSON.stringify(result.LastEvaluatedKey) : null,
            hasMore: !!result.LastEvaluatedKey
        });
    } catch (error) {
        console.error('Error fetching comments:', error);
        return res.status(500).json({ 
            success: false,
            error: 'Failed to fetch comments',
            details: error.message
        });
    }
});

// Delete a comment
app.delete('/deletecomment', async (req, res) => {
    const { postId, commentId } = req.body;

    // Basic validation
    if (!postId || !commentId) {
        return res.status(400).json({ 
            success: false,
            error: 'Missing required fields: postId and commentId are required' 
        });
    }

    try {
        // Delete the comment directly using the composite key
        await dynamoDB.send(new DeleteCommand({
            TableName: 'comments',
            Key: {
                commentId: commentId,  // partition key
                postId: postId     // sort key
            }
        }));

        // Decrement the comments count in posts table
        await dynamoDB.send(new UpdateCommand({
            TableName: 'posts',
            Key: { 
                postId: postId 
            },
            UpdateExpression: 'SET comments = if_not_exists(comments, :zero) - :decrement',
            ExpressionAttributeValues: { 
                ':decrement': 1,
                ':zero': 0
            }
        }));

        res.status(200).json({ 
            success: true,
            message: 'Comment deleted successfully' 
        });
    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to delete comment', 
            details: error.message 
        });
    }
});

app.post('/followuser', async (req, res) => {
    const { followerUserId, followingUserId } = req.body;

    if (!followerUserId || !followingUserId) {
        return res.status(400).json({ message: 'Missing args' });
    }

    const followId = `f${uuidv4().replace(/-/g, '')}`;
    const date = new Date().toISOString();

    try {
        // Check if already following using Scan
        const existingFollow = await dynamoDB.send(new ScanCommand({
            TableName: 'followers',
            FilterExpression: 'followerUserId = :frid AND followingUserId = :fwid',
            ExpressionAttributeValues: {
                ':frid': followerUserId,
                ':fwid': followingUserId
            }
        }));

        if (existingFollow.Items && existingFollow.Items.length > 0) {
            return res.status(400).json({ message: 'Already following this user' });
        }

        // Insert follow relationship with new followId
        await dynamoDB.send(new PutCommand({
            TableName: 'followers',
            Item: {
                followId,           // Primary key
                followingUserId,    // GSI partition key
                followerUserId,     // Additional attribute
                date
            }
        }));

        // Update follower's following count
        await dynamoDB.send(new UpdateCommand({
            TableName: 'user_details',
            Key: { userId: followerUserId },
            UpdateExpression: 'SET following = if_not_exists(following, :zero) + :increment',
            ExpressionAttributeValues: { ':increment': 1, ':zero': 0 }
        }));

        // Update following user's followers count
        await dynamoDB.send(new UpdateCommand({
            TableName: 'user_details',
            Key: { userId: followingUserId },
            UpdateExpression: 'SET followers = if_not_exists(followers, :zero) + :increment',
            ExpressionAttributeValues: { ':increment': 1, ':zero': 0 }
        }));

        res.status(200).json({ success: true, message: 'Followed successfully', followId });

    } catch (error) {
        console.error("DynamoDB Error:", error);
        res.status(500).json({ error: 'Unable to follow', details: error.message });
    }
});

// Check follow status endpoint
app.get('/checkfollowstatus/:followerUserId/:followingUserId', async (req, res) => {
    const { followerUserId, followingUserId } = req.params;

    if (!followerUserId || !followingUserId) {
        return res.status(400).json({
            success: false,
            message: 'Missing user IDs'
        });
    }

    try {
        const params = {
            TableName: 'followers',
            FilterExpression: 'followerUserId = :frid AND followingUserId = :fwid',
            ExpressionAttributeValues: {
                ':frid': followerUserId,
                ':fwid': followingUserId
            }
        };

        const data = await dynamoDB.send(new ScanCommand(params));
        const isFollowing = data.Items && data.Items.length > 0;
        const followId = isFollowing ? data.Items[0].followId : null;

        res.json({
            success: true,
            isFollowing,
            followId
        });

    } catch (error) {
        console.error("DynamoDB Error:", error);
        res.status(500).json({
            success: false,
            error: 'Error checking follow status',
            details: error.message
        });
    }
});

app.delete('/unfollowuser', async (req, res) => {
    const { followerUserId, followingUserId } = req.body;

    if (!followerUserId || !followingUserId) {
        return res.status(400).json({ 
            success: false,
            message: 'Missing required fields: followerUserId and followingUserId are required' 
        });
    }

    try {
        // First find the follow relationship to get the followId
        const existingFollow = await dynamoDB.send(new ScanCommand({
            TableName: 'followers',
            FilterExpression: 'followerUserId = :frid AND followingUserId = :fwid',
            ExpressionAttributeValues: {
                ':frid': followerUserId,
                ':fwid': followingUserId
            }
        }));

        if (!existingFollow.Items || existingFollow.Items.length === 0) {
            return res.status(404).json({ 
                success: false,
                message: 'Follow relationship not found' 
            });
        }

        const followId = existingFollow.Items[0].followId;

        // Delete follow relationship using followId
        await dynamoDB.send(new DeleteCommand({
            TableName: 'followers',
            Key: {
                followId: followId  // Use followId as primary key
            }
        }));

        // Decrement follower's following count
        await dynamoDB.send(new UpdateCommand({
            TableName: 'user_details',
            Key: { userId: followerUserId },
            UpdateExpression: 'SET following = if_not_exists(following, :zero) + :decrement',
            ExpressionAttributeValues: { 
                ':decrement': -1, 
                ':zero': 0 
            }
        }));

        // Decrement following user's followers count
        await dynamoDB.send(new UpdateCommand({
            TableName: 'user_details',
            Key: { userId: followingUserId },
            UpdateExpression: 'SET followers = if_not_exists(followers, :zero) + :decrement',
            ExpressionAttributeValues: { 
                ':decrement': -1, 
                ':zero': 0 
            }
        }));

        res.status(200).json({ 
            success: true, 
            message: 'Unfollowed successfully' 
        });

    } catch (error) {
        console.error("DynamoDB Error:", error);
        res.status(500).json({ 
            success: false,
            error: 'Error unfollowing user', 
            details: error.message 
        });
    }
});

// Get user following/followers helper function
async function scanComplete(params) {
    let items = [];
    let lastEvaluatedKey = null;
    
    do {
        if (lastEvaluatedKey) {
            params.ExclusiveStartKey = lastEvaluatedKey;
        }
        
        const response = await dynamoDB.send(new ScanCommand(params));
        items = items.concat(response.Items);
        lastEvaluatedKey = response.LastEvaluatedKey;
    } while (lastEvaluatedKey);
    
    return items;
}

// Get user following endpoint
app.get('/userfollowing/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        const params = {
            TableName: 'followers',
            FilterExpression: 'followerUserId = :userId',
            ExpressionAttributeValues: {
                ':userId': userId
            }
        };

        const followingData = await scanComplete(params);
        const followingIds = followingData.map(item => item.followingUserId);

        if (followingIds.length === 0) {
            return res.json({ following: [] });
        }

        const userDetailsPromises = followingIds.map(followingId => 
            dynamoDB.send(new GetCommand({
                TableName: 'user_details',
                Key: { userId: followingId }
            }))
        );

        const userDetailsResponses = await Promise.all(userDetailsPromises);
        const following = userDetailsResponses
            .map((response, index) => {
                const userDetail = response.Item;
                if (!userDetail) return null;
                
                const followRecord = followingData[index];
                return {
                    userId: followingIds[index],
                    username: userDetail.username,
                    fullname: userDetail.fullname,
                    profileUrl: userDetail.profileUrl || '',
                    followId: followRecord.followId // Include followId in response
                };
            })
            .filter(item => item !== null);

        res.json({ following });
    } catch (error) {
        console.error("DynamoDB Error:", error);
        res.status(500).json({ error: 'Error getting following list', details: error.message });
    }
});

// Get user followers endpoint
app.get('/userfollowers/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        const params = {
            TableName: 'followers',
            FilterExpression: 'followingUserId = :userId',
            ExpressionAttributeValues: {
                ':userId': userId
            }
        };

        const followerData = await scanComplete(params);
        const followerIds = followerData.map(item => item.followerUserId);

        if (followerIds.length === 0) {
            return res.json({ followers: [] });
        }

        const userDetailsPromises = followerIds.map(followerId => 
            dynamoDB.send(new GetCommand({
                TableName: 'user_details',
                Key: { userId: followerId }
            }))
        );

        const userDetailsResponses = await Promise.all(userDetailsPromises);
        const followers = userDetailsResponses
            .map((response, index) => {
                const userDetail = response.Item;
                if (!userDetail) return null;
                
                const followRecord = followerData[index];
                return {
                    userId: followerIds[index],
                    username: userDetail.username,
                    fullname: userDetail.fullname,
                    profileUrl: userDetail.profileUrl || '',
                    followId: followRecord.followId // Include followId in response
                };
            })
            .filter(item => item !== null);

        res.json({ followers });
    } catch (error) {
        console.error("DynamoDB Error:", error);
        res.status(500).json({ error: 'Error getting followers list', details: error.message });
    }
});

// Generate a unique encryption key for each sender-recipient pair
const generateEncryptionKey = (senderId, recipientId) => {
    // Sort IDs to ensure same key regardless of sender/recipient order
    const ids = [senderId, recipientId].sort();
    // Create a consistent key using both IDs
    return CryptoJS.SHA256(ids.join('_')).toString();
};

const encryptMessage = (text, senderId, recipientId) => {
    try {
        if (!text || !senderId || !recipientId) {
            throw new Error('Missing required parameters for encryption');
        }

        // Generate encryption key specific to this sender-recipient pair
        const encryptionKey = generateEncryptionKey(senderId, recipientId);

        // Add a timestamp to prevent replay attacks
        const messageWithTimestamp = JSON.stringify({
            content: text,
            timestamp: Date.now()
        });

        // Encrypt the message
        const encrypted = CryptoJS.AES.encrypt(messageWithTimestamp, encryptionKey);
        
        // Return the encrypted message as a string
        return encrypted.toString();
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt message');
    }
};

const decryptMessage = (encryptedText, senderId, recipientId) => {
    try {
        if (!encryptedText || !senderId || !recipientId) {
            throw new Error('Missing required parameters for decryption');
        }

        // Generate the same encryption key
        const encryptionKey = generateEncryptionKey(senderId, recipientId);

        // Decrypt the message
        const decrypted = CryptoJS.AES.decrypt(encryptedText, encryptionKey);
        const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);

        if (!decryptedString) {
            throw new Error('Decryption resulted in empty string');
        }

        // Parse the message and timestamp
        const { content, timestamp } = JSON.parse(decryptedString);

        // Optional: Add timestamp validation if needed
        const messageAge = Date.now() - timestamp;
        if (messageAge > 24 * 60 * 60 * 1000) { // 24 hours
            console.warn('Message is older than 24 hours');
        }

        return content;
    } catch (error) {
        console.error('Decryption error:', error);
        return null; // Return null for failed decryption
    }
};

app.post('/storeMessage', async (req, res) => {
    const { senderId, recipientId, text, messageId, createdAt } = req.body;

    if (!senderId || !recipientId || !text || !messageId || !createdAt) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const encryptedText = encryptMessage(text, senderId, recipientId); // Encrypt here

        await dynamoDB.send(new PutCommand({
            TableName: 'talks',
            Item: {
                messageId,
                senderId,
                recipientId,
                text: encryptedText, // Store the encrypted text
                createdAt
            }
        }));

        res.status(200).json({ message: 'Message stored successfully' });
    } catch (error) {
        console.error('Error storing message:', error);
        res.status(500).json({ error: 'Failed to store message' });
    }
});

app.get('/getPendingMessages', async (req, res) => {
    const { userId } = req.query;

    if (!userId) {
        return res.status(400).json({ error: 'UserId is required' });
    }

    try {
        const result = await dynamoDB.send(new ScanCommand({
            TableName: 'talks',
            FilterExpression: 'recipientId = :userId',
            ExpressionAttributeValues: { ':userId': userId }
        }));

        const messages = result.Items || [];
        const decryptedMessages = messages.map(message => {
            const decryptedText = decryptMessage(message.text, message.senderId, userId);
            if (decryptedText) { // Only include if decryption successful
                return {
                    ...message,
                    text: decryptedText
                };
            }
            return null; // Or handle decryption failure as needed
        }).filter(msg => msg !== null); // Filter out failed decryptions

        res.status(200).json({ messages: decryptedMessages });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

app.post('/deleteSeenMessages', async (req, res) => {
    const { messageIds } = req.body;

    if (!messageIds || !Array.isArray(messageIds)) {
        return res.status(400).json({ error: 'messageIds array is required' });
    }

    try {
        for (const messageId of messageIds) {
            await dynamoDB.send(new DeleteCommand({
                TableName: 'talks',
                Key: { messageId }
            }));
        }

        res.status(200).json({ message: 'Messages deleted successfully' });
    } catch (error) {
        console.error('Error deleting messages:', error);
        res.status(500).json({ error: 'Failed to delete messages' });
    }
});

app.post('/reportuser', async (req, res) => {

    const { reporterId, reportedUserId, timestamp, reason } = req.body;

    if (!reportedUserId || !timestamp || !reporterId || !reason) {
        return res.status(400).json({ error: 'Cannot request due to unfilled information...' });
    }

    const reportId = uuidv4();

    try {
        const result = await dynamoDB.send(new PutCommand({
            TableName: 'report',
            Item: {
                reportId,
                postId:'userreports',
                reporterId,
                reportedUserId,
                reason,
                timestamp
            }
        }));
        
        console.log('DynamoDB response:', JSON.stringify(result));
        return res.status(201).json({ message: 'Reported Successfully!' });
    } catch (error) {
        console.error('Detailed DynamoDB error:', error);
        console.error('Error stack:', error.stack);
        return res.status(500).json({ error: 'Failed to report message' });
    }
});

app.get('/getuserreports', async (req, res) => {
    try {
        const reportParams = {
            TableName: 'report',
            FilterExpression: 'postId = :postId',
            ExpressionAttributeValues: {
                ':postId': 'userreports'
            }
        };

        let reports = [];
        let lastEvaluatedKey = null;

        do {
            const command = new ScanCommand(reportParams);
            const data = await dynamoDB.send(command);

            reports = reports.concat(data.Items);
            lastEvaluatedKey = data.LastEvaluatedKey;
            reportParams.ExclusiveStartKey = lastEvaluatedKey;

        } while (lastEvaluatedKey);

        console.log("Reports Data:", reports);

        if (!reports.length) {
            return res.json({ reports: [] });
        }

        const reportedUserIds = [...new Set(reports.map(r => r.reportedUserId))];

        // Fetch user details
        const userDetailsPromises = reportedUserIds.map(async (userId) => {
            try {
                const userParams = {
                    TableName: 'user_details',
                    Key: { userId }
                };

                const command = new GetCommand(userParams);
                const userData = await dynamoDB.send(command);

                return userData.Item ? { userId, ...userData.Item } : null;
            } catch (err) {
                console.error(`Error fetching user details for ${userId}:`, err);
                return null;
            }
        });

        const userDetails = await Promise.all(userDetailsPromises);
        const filteredUserDetails = userDetails.filter(user => user !== null);

        const finalData = reports.map(report => ({
            ...report,
            reportedUserData: filteredUserDetails.find(user => user.userId === report.reportedUserId) || null
        }));

        console.log("Final Data Sent:", finalData);
        res.json({ reports: finalData });

    } catch (error) {
        console.error("DynamoDB Error:", error);
        res.status(500).json({ error: 'Error getting reported users', details: error.message });
    }
});


app.get('/getpostreports', async (req, res) => {
    try {
        const reportParams = {
            TableName: 'report',
            FilterExpression: 'postId <> :postId', // Changed to "not equal"
            ExpressionAttributeValues: {
                ':postId': 'userreports'
            }
        };

        let reports = [];
        let lastEvaluatedKey = null;

        do {
            const command = new ScanCommand(reportParams);
            const data = await dynamoDB.send(command);

            reports = reports.concat(data.Items);
            lastEvaluatedKey = data.LastEvaluatedKey;
            reportParams.ExclusiveStartKey = lastEvaluatedKey;

        } while (lastEvaluatedKey);

        console.log("Reports Data:", reports);

        if (!reports.length) {
            return res.json({ reports: [] });
        }

        const reportedUserIds = [...new Set(reports.map(r => r.reportedUserId))];

        // Fetch user details
        const userDetailsPromises = reportedUserIds.map(async (userId) => {
            try {
                const userParams = {
                    TableName: 'user_details',
                    Key: { userId }
                };

                const command = new GetCommand(userParams);
                const userData = await dynamoDB.send(command);

                return userData.Item ? { userId, ...userData.Item } : null;
            } catch (err) {
                console.error(`Error fetching user details for ${userId}:`, err);
                return null;
            }
        });

        const userDetails = await Promise.all(userDetailsPromises);
        const filteredUserDetails = userDetails.filter(user => user !== null);

        const finalData = reports.map(report => ({
            ...report,
            reportedUserData: filteredUserDetails.find(user => user.userId === report.reportedUserId) || null
        }));

        console.log("Final Data Sent:", finalData);
        res.json({ reports: finalData });

    } catch (error) {
        console.error("DynamoDB Error:", error);
        res.status(500).json({ error: 'Error getting reported users', details: error.message });
    }
});

app.get('/getspecifiedpost/:postId', async (req, res) => {
    try {
        const postId = req.params.postId;

        const postParams = {
            TableName: 'posts',
            Key: {
                postId: postId
            }
        };

        const postResult = await dynamoDB.send(new GetCommand(postParams));

        if (!postResult.Item) {
            return res.status(404).json({ error: 'Post not found.' });
        }

        const post = postResult.Item;

        try {
            const userParams = {
                TableName: 'user_details',
                Key: { userId: post.userId }
            };

            const userResult = await dynamoDB.send(new GetCommand(userParams));
            const user = userResult.Item;

            const postWithUserDetails = {
                ...post,
                username: user?.username || 'Unknown User',
                profileUrl: user?.profileUrl || '',
                fullname: user?.fullname || '',
            };

            res.status(200).json(postWithUserDetails);
        } catch (userError) {
            console.error(`Error fetching user for post ${postId}:`, userError);
            const postWithUserDetails = {
                ...post,
                username: 'Unknown User',
                profileUrl: '',
                fullname: '',
            };
            res.status(200).json(postWithUserDetails);

        }

    } catch (error) {
        console.error('Error fetching specified post:', error);
        res.status(500).json({ error: 'Failed to fetch specified post.' });
    }
});

startServer();