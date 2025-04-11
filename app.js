// app.js

const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const http = require('http');
const socketIo = require('socket.io');
require("dotenv").config();
const db = require("./config/Database");

const app = express();
const port = process.env.PORT;

// Use middleware to parse JSON bodies and handle CORS
app.use(bodyParser.json());
app.use(cors());

// Create an HTTP server and attach Socket.IO for real-time notifications
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: '*' }
});

// Mapping to store connected users (userId -> socketId)
const connectedUsers = {};

// Socket.IO event handlers
io.on('connection', (socket) => {
  console.log('A user connected: ' + socket.id);

  // Register the socket with a userId
  socket.on('register', (userId) => {
    connectedUsers[userId] = socket.id;
    console.log(`User ${userId} registered with socket id: ${socket.id}`);
  });

  // Remove the user from the mapping upon disconnect
  socket.on('disconnect', () => {
    for (const [userId, sockId] of Object.entries(connectedUsers)) {
      if (sockId === socket.id) {
        delete connectedUsers[userId];
        console.log(`User ${userId} disconnected.`);
        break;
      }
    }
  });
});

// Secret key for JWT (store securely in production)
const SECRET_KEY = 'your-secret-key';

// Configure Multer to store uploaded files in memory
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Configure Cloudinary using environment variables
cloudinary.config({
  cloud_name: process.env.CLOUDNAME,
  api_key: process.env.APIKEY,
  api_secret: process.env.APISECRET
});

// Middleware to authenticate requests using JWT

function authenticateToken(req, res, next) {
  const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ---------------------- User Endpoints ----------------------

// Login user and generate a JWT
app.post('/api/wallet-login', (req, res) => {
  const { walletAddress } = req.body;

  if (!walletAddress) {
    return res.status(400).json({ error: 'Wallet address is required.' });
  }

  const token = jwt.sign({ walletAddress }, SECRET_KEY);
  res.json({ token, walletAddress });
});



app.get('/api/users', authenticateToken, (req, res) => {
  const sqlQuery = 'SELECT * FROM users';
  db.query(sqlQuery, (error, results) => {
    if (error) {
      console.error('Error fetching users:', error);
      return res.status(500).json({ error: 'An error occurred while retrieving the users.' });
    }
    res.json(results);
  });
});














app.post('/api/user/fromWalletAddress', (req, res) => {
  const { walletAddress } = req.body;

  if (!walletAddress) {
    return res.status(400).json({ error: 'Missing walletAddress parameter' });
  }

  // Step 1: Get wallet_id from walletconnect
  const walletSql = 'SELECT wallet_id FROM walletconnect WHERE walletaddress = ?';

  db.query(walletSql, [walletAddress], (walletErr, walletResults) => {
    if (walletErr) {
      console.error('Database error (wallet lookup):', walletErr);
      return res.status(500).json({ error: 'Database fetch failed (wallet)' });
    }

    if (walletResults.length === 0) {
      return res.status(404).json({ error: 'Wallet not found' });
    }

    const wallet_id = walletResults[0].wallet_id;

    // Step 2: Get user info using wallet_id
    const userSql = `
      SELECT username, display_picture, bio, created_at, last_seen 
      FROM users 
      WHERE wallet_FK = ?
    `;

    db.query(userSql, [wallet_id], (userErr, userResults) => {
      if (userErr) {
        console.error('Database error (user lookup):', userErr);
        return res.status(500).json({ error: 'Database fetch failed (user)' });
      }

      if (userResults.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({
        wallet_id,
        user: userResults[0]
      });
    });
  });
});



app.get("/api/getwallet_id", authenticateToken, (req, res) => {
  const { walletaddress } = req.query; // Notice the change here
  if (!walletaddress) {
    return res.status(400).json({ error: "Wallet Address is required." });
  }
  
  const checkQuery = "SELECT * FROM walletconnect WHERE walletaddress = ?";
  db.query(checkQuery, [walletaddress], (err, results) => {
    if (err) {
      return res.status(500).json({ error: "There is an error.", details: err });
    }
    if (results.length > 0) {
      return res.status(200).json({ message: "Wallet id successfully fetched", wallet: results });
    } else {
      return res.status(404).json({ error: "Wallet not found." });
    }
  });
});




app.get("/api/getallwallet", authenticateToken, (req, res) => {

  const checkQuery = "SELECT * FROM walletconnect";
  db.query(checkQuery, (err, results) => {
    if (err) {
      return res.status(500).json({ error: "There is an error.", details: err });
    }
    if (results.length > 0) {

      return res.status(200).json({ message: "Wallet users successfully fetched", wallet: results });
    } else {
      return res.status(404).json({ error: "Wallet not found." });
    }
  });
});












// Logout user and update the last_seen timestamp
app.post('/api/logout', authenticateToken, (req, res) => {
  res.json({ message: 'User logged out successfully' });
});

// Register a new user with an optional profile picture upload



app.post('/api/register', authenticateToken, upload.single('display_picture'), (req, res) => {
  const { username, bio, wallet_id } = req.body;

  // Validate input
  if (!username || !bio || !wallet_id) {
    return res.status(400).json({ error: 'Username, bio, and wallet_id are required.' });
  }

  // Check for duplicate username
  const checkQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(checkQuery, [username], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error on username check.', details: err });
    if (results.length > 0) {
      return res.status(400).json({ error: 'A user with the same username already exists.' });
    }

    // Function to insert user
    const insertUser = (display_picture = null) => {
      const insertQuery = `
        INSERT INTO users (username, display_picture, bio, wallet_FK)
        VALUES (?, ?, ?, ?)
      `;
      db.query(insertQuery, [username, display_picture, bio, wallet_id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error on user insert.', details: err });
        res.json({ message: 'User registered successfully', userId: result.insertId });
      });
    };

    // Handle display_picture (if provided)
    if (req.file) {
      const streamUpload = (buffer) => {
        return new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'users' },
            (error, result) => {
              if (result) resolve(result);
              else reject(error);
            }
          );
          streamifier.createReadStream(buffer).pipe(stream);
        });
      };

      streamUpload(req.file.buffer)
        .then((uploadResult) => {
          insertUser(uploadResult.secure_url);
        })
        .catch((error) => {
          res.status(500).json({ error: 'Image upload failed.', details: error.message });
        });
    } else {
      insertUser(); // No image uploaded
    }
  });
});


// ---------------------- Chatroom Endpoints ----------------------

// Retrieve all chatrooms ordered by newest first
app.get('/api/chatrooms/:created_by', authenticateToken, (req, res) => {
  const createdBy = req.params.created_by; // Retrieve the created_by parameter from the URL
  const query = `SELECT * FROM chatrooms WHERE created_by = ? ORDER BY created_at DESC`;
  
  // Using a parameterized query to prevent SQL injection
  db.query(query, [createdBy], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err });
    }
    res.json(results);
  });
});


app.get('/api/chatrooms/:wallet_id', authenticateToken, (req, res) => {
  const query = `SELECT * FROM chatrooms ORDER BY created_at DESC`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});




// Fetch a single posting by its ID
app.get('/api/postings/:user_id', authenticateToken, (req, res) => {
  const { user_id } = req.params;
 const sql = 'SELECT * FROM postings WHERE user_id = ? ORDER BY id DESC';
  db.query(sql, [user_id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: 'Database fetch failed' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Posting not found' });
    }
    res.send(results);
  });
});

// Fetch all postings
app.get('/api/postings', authenticateToken, (req, res) => {
  const { user_id } = req.params;
 const sql = 'SELECT * FROM postings ORDER BY id DESC';
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: 'Database fetch failed' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Posting not found' });
    }
    res.send(results);
  });
});




// Create a new chatroom with an optional display picture
app.post('/api/chatrooms/:created_by', authenticateToken, upload.single('display_picture'), (req, res) => {
  const { name, details } = req.body;
  const createdBy = req.params.created_by;

  if (req.file) {
    const streamUpload = (buffer) => {
      return new Promise((resolve, reject) => {
        let stream = cloudinary.uploader.upload_stream(
          { folder: 'chat_room' },
          (error, result) => {
            if (result) resolve(result);
            else reject(error);
          }
        );
        streamifier.createReadStream(buffer).pipe(stream);
      });
    };

    streamUpload(req.file.buffer)
      .then((result) => {
        const displayPicture = result.secure_url;
        const query = 'INSERT INTO chatrooms (name, details, created_by, display_picture) VALUES (?, ?, ?, ?)';
        db.query(query, [name, details, createdBy, displayPicture], (err, result) => {
          if (err) return res.status(500).json({ error: err });
          const chatroomId = result.insertId;
          // Add creator as admin
          const memberQuery = 'INSERT INTO chatroom_members (chatroom_id, user_id, role) VALUES (?, ?, ?)';
          db.query(memberQuery, [chatroomId, createdBy, 'admin'], (err2) => {
            if (err2) return res.status(500).json({ error: err2 });
            res.json({ message: 'Chatroom created successfully', chatroomId });
          });
        });
      })
      .catch((error) => {
        res.status(500).json({ error: error.message });
      });
  } else {
    const query = 'INSERT INTO chatrooms (name, details, created_by) VALUES (?, ?, ?)';
    db.query(query, [name, details, createdBy], (err, result) => {
      if (err) return res.status(500).json({ error: err });
      const chatroomId = result.insertId;
      const memberQuery = 'INSERT INTO chatroom_members (chatroom_id, user_id, role) VALUES (?, ?, ?)';
      db.query(memberQuery, [chatroomId, createdBy, 'admin'], (err2) => {
        if (err2) return res.status(500).json({ error: err2 });
        res.json({ message: 'Chatroom created successfully', chatroomId });
      });
    });
  }
});

// Add a member to a chatroom (admin only)
app.post('/api/chatrooms/:id/:currentUserId/add', authenticateToken, (req, res) => {
  const chatroomId = req.params.id;
  const { wallet_id } = req.body;
  const currentUserId = req.params.currentUserId;
    
    // Verify that the user exists
    const userCheckQuery = 'SELECT * FROM walletconnect WHERE wallet_id = ?';
    db.query(userCheckQuery, [wallet_id], (err, userResults) => {
      if (err) return res.status(500).json({ error: err });
      if (userResults.length === 0)
        return res.status(400).json({ error: 'User is not registered' });
      
      // Ensure the user is not already a member
      const memberCheckQuery = 'SELECT * FROM chatroom_members WHERE chatroom_id = ? AND user_id = ?';
      db.query(memberCheckQuery, [chatroomId, wallet_id], (err, memberResults) => {
        if (err) return res.status(500).json({ error: err });
        if (memberResults.length > 0)
          return res.status(400).json({ error: 'User is already a member' });
        
        // Add the user as a member
        const addQuery = 'INSERT INTO chatroom_members (chatroom_id, user_id, role) VALUES (?, ?, "member")';
        db.query(addQuery, [chatroomId, wallet_id], (err2) => {
          if (err2) return res.status(500).json({ error: err2 });
          res.json({ message: 'Member added successfully' });
        });
      });
    });
  });
});

// Remove a member from a chatroom (admin only)
app.delete('/api/chatrooms/:id/remove', authenticateToken, (req, res) => {
  const chatroomId = req.params.id;
  const { userId } = req.body;
  const currentUserId = req.user.id;

  const adminQuery = 'SELECT * FROM chatroom_members WHERE chatroom_id = ? AND user_id = ? AND role = "admin"';
  db.query(adminQuery, [chatroomId, currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (results.length === 0)
      return res.status(403).json({ error: 'Only admin can remove members' });

    const removeQuery = 'DELETE FROM chatroom_members WHERE chatroom_id = ? AND user_id = ?';
    db.query(removeQuery, [chatroomId, userId], (err2) => {
      if (err2) return res.status(500).json({ error: err2 });
      res.json({ message: 'Member removed successfully' });
    });
  });
});

// Delete a chatroom (admin only), also removing its messages and members
app.delete('/api/chatrooms/:id', authenticateToken, (req, res) => {
  const chatroomId = req.params.id;
  const currentUserId = req.user.id;

  const adminQuery = 'SELECT * FROM chatroom_members WHERE chatroom_id = ? AND user_id = ? AND role = "admin"';
  db.query(adminQuery, [chatroomId, currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (results.length === 0)
      return res.status(403).json({ error: 'Only admin can delete the chatroom' });

    // Delete related messages and members before deleting the chatroom
    db.query('DELETE FROM messages WHERE chatroom_id = ?', [chatroomId]);
    db.query('DELETE FROM chatroom_members WHERE chatroom_id = ?', [chatroomId]);
    const deleteQuery = 'DELETE FROM chatrooms WHERE id = ?';
    db.query(deleteQuery, [chatroomId], (err2) => {
      if (err2) return res.status(500).json({ error: err2 });
      res.json({ message: 'Chatroom deleted successfully' });
    });
  });
});

// Retrieve all messages from a chatroom (only for members)
app.get('/api/chatrooms/:id/messages', authenticateToken, (req, res) => {
  const chatroomId = req.params.id;
  const currentUserId = req.user.id;
  
  // Verify that the current user is a member of the chatroom
  const checkQuery = 'SELECT * FROM chatroom_members WHERE chatroom_id = ? AND user_id = ?';
  db.query(checkQuery, [chatroomId, currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (results.length === 0)
      return res.status(403).json({ error: 'Access denied. You are not a member of this chatroom.' });

    // Get messages along with the sender's username
    const msgQuery = `
      SELECT m.*, u.username 
      FROM messages m JOIN users u ON m.user_id = u.id 
      WHERE chatroom_id = ? 
      ORDER BY created_at ASC
    `;
    db.query(msgQuery, [chatroomId], (err2, messages) => {
      if (err2) return res.status(500).json({ error: err2 });
      res.json(messages);
    });
  });
});

// Post a new message to a chatroom with optional attachment upload
app.post('/api/chatrooms/:id/messages', authenticateToken, upload.single('attachment'), (req, res) => {
  const chatroomId = req.params.id;
  const { message } = req.body;
  const currentUserId = req.user.id;

  // Verify membership in the chatroom
  const checkQuery = 'SELECT * FROM chatroom_members WHERE chatroom_id = ? AND user_id = ?';
  db.query(checkQuery, [chatroomId, currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (results.length === 0)
      return res.status(403).json({ error: 'Access denied. You are not a member of this chatroom.' });

    // Helper function to notify other members about the new message
    const notifyMembers = (attachment_url = null) => {
      const getChatroomQuery = 'SELECT name FROM chatrooms WHERE id = ?';
      db.query(getChatroomQuery, [chatroomId], (err, chatroomResults) => {
        if (err) {
          console.error('Error fetching chatroom name:', err);
          return;
        }
        const chatroomName = (chatroomResults && chatroomResults.length > 0) ? chatroomResults[0].name : '';
        const getSenderQuery = 'SELECT username FROM users WHERE id = ?';
        db.query(getSenderQuery, [currentUserId], (err, senderResults) => {
          if (err) {
            console.error('Error fetching sender username:', err);
            return;
          }
          const senderUsername = (senderResults && senderResults.length > 0) ? senderResults[0].username : '';
          const getMembersQuery = 'SELECT user_id FROM chatroom_members WHERE chatroom_id = ?';
          db.query(getMembersQuery, [chatroomId], (err, members) => {
            if (err) {
              console.error('Error fetching chatroom members:', err);
              return;
            }
            members.forEach((member) => {
              if (member.user_id !== currentUserId && connectedUsers[member.user_id]) {
                io.to(connectedUsers[member.user_id]).emit('newPersonalMessage', {
                  chatroom_id: chatroomId,
                  chatroom_name: chatroomName,
                  sender_id: currentUserId,
                  sender_username: senderUsername,
                  message,
                  attachment_url,
                  created_at: new Date()
                });
              }
            });
          });
        });
      });
    };

    if (req.file) {
      const streamUpload = (buffer) => {
        return new Promise((resolve, reject) => {
          let stream = cloudinary.uploader.upload_stream((error, result) => {
            if (result) resolve(result);
            else reject(error);
          });
          streamifier.createReadStream(buffer).pipe(stream);
        });
      };

      streamUpload(req.file.buffer)
        .then((result) => {
          const attachment_url = result.secure_url;
          const insertQuery = `
            INSERT INTO messages (chatroom_id, user_id, message, attachment_url, is_read) 
            VALUES (?, ?, ?, ?, 0)
          `;
          db.query(insertQuery, [chatroomId, currentUserId, message, attachment_url], (err2) => {
            if (err2) return res.status(500).json({ error: err2 });
            notifyMembers(attachment_url);
            res.json({ message: 'Message with attachment posted successfully' });
          });
        })
        .catch((error) => {
          res.status(500).json({ error: error.message });
        });
    } else {
      const insertQuery = `
        INSERT INTO messages (chatroom_id, user_id, message, is_read) 
        VALUES (?, ?, ?, 0)
      `;
      db.query(insertQuery, [chatroomId, currentUserId, message], (err2) => {
        if (err2) return res.status(500).json({ error: err2 });
        notifyMembers();
        res.json({ message: 'Message posted successfully' });
      });
    }
  });
});

// Mark all messages in a chatroom as read (excluding messages sent by the current user)
app.post('/api/chatrooms/:id/mark-read', authenticateToken, (req, res) => {
  const chatroomId = req.params.id;
  const currentUserId = req.user.id;
  const updateQuery = `
    UPDATE messages 
    SET is_read = 1 
    WHERE chatroom_id = ? AND user_id != ? AND is_read = 0
  `;
  db.query(updateQuery, [chatroomId, currentUserId], (err) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Chatroom messages marked as read' });
  });
});

// Get the unread message count for a chatroom (excluding the current user's messages)
app.get('/api/chatrooms/:id/unread-count', authenticateToken, (req, res) => {
  const chatroomId = req.params.id;
  const currentUserId = req.user.id;
  const countQuery = `
    SELECT COUNT(*) AS unreadCount 
    FROM messages 
    WHERE chatroom_id = ? AND user_id != ? AND is_read = 0
  `;
  db.query(countQuery, [chatroomId, currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results[0]);
  });
});

// ---------------------- Personal Message Endpoints ----------------------

// Search for registered users by username (excluding the current user)
app.get('/api/users', (req, res) => {
  const search = req.query.search || '';
  const query = 'SELECT id, username, email FROM users WHERE username LIKE ? AND id != ?';
  db.query(query, [`%${search}%`, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

// Get personal chat messages between the current user and another user
app.get('/api/personal-chat/:walletId1/:walletId2/messages', authenticateToken, (req, res) => {
  const walletId1 = req.params.walletId1;
  const walletId2 = req.params.walletId2;
  const query = `
    SELECT pm.*, 
           wc_sender.walletaddress AS sender_walletaddress, 
           wc_receiver.walletaddress AS receiver_walletaddress
    FROM personal_messages pm
    JOIN walletconnect wc_sender ON pm.sender_id = wc_sender.wallet_id
    JOIN walletconnect wc_receiver ON pm.receiver_id = wc_receiver.wallet_id
    WHERE (pm.sender_id = ? AND pm.receiver_id = ?)
       OR (pm.sender_id = ? AND pm.receiver_id = ?)
    ORDER BY pm.created_at ASC
  `;
  db.query(query, [walletId1, walletId2, walletId2, walletId1], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});



// Post a personal message (with optional attachment) to a specific user
app.post('/api/personal-chat/:userId/:senderId/messages', 
  authenticateToken, 
  upload.single('attachment_url'), 
  (req, res) => {
    const otherUserId = req.params.userId;
    const currentUserId = req.params.senderId;
    const { message } = req.body;

    // Helper function to upload to Cloudinary already defined above
    const streamUpload = (buffer) => {
      return new Promise((resolve, reject) => {
        let stream = cloudinary.uploader.upload_stream((error, result) => {
          if (result) resolve(result);
          else reject(error);
        });
        streamifier.createReadStream(buffer).pipe(stream);
      });
    };

    if (req.file) {
      // If a file exists, upload it to Cloudinary
      streamUpload(req.file.buffer)
        .then((result) => {
          const attachment_url = result.secure_url;
          // Insert the personal message along with the attachment_url into the database
          const insertQuery = `
            INSERT INTO personal_messages (sender_id, receiver_id, message, attachment_url, is_read) 
            VALUES (?, ?, ?, ?, 0)
          `;
          db.query(insertQuery, [currentUserId, otherUserId, message, attachment_url], (err) => {
            if (err) return res.status(500).json({ error: err });
            const recipientSocketId = connectedUsers[otherUserId];
            if (recipientSocketId) {
              io.to(recipientSocketId).emit('newPersonalMessage', {
                sender_id: currentUserId,
                receiver_id: otherUserId,
                message,
                attachment_url,
                created_at: new Date()
              });
            }
            res.json({ message: 'Personal message with attachment sent successfully' });
          });
        })
        .catch((error) => {
          res.status(500).json({ error: error.message });
        });
    } else {
      // If no file is sent, insert the message normally
      const insertQuery = `
        INSERT INTO personal_messages (sender_id, receiver_id, message, is_read) 
        VALUES (?, ?, ?, 0)
      `;
      db.query(insertQuery, [currentUserId, otherUserId, message], (err) => {
        if (err) return res.status(500).json({ error: err });
        const recipientSocketId = connectedUsers[otherUserId];
        if (recipientSocketId) {
          io.to(recipientSocketId).emit('newPersonalMessage', {
            sender_id: currentUserId,
            receiver_id: otherUserId,
            message,
            created_at: new Date()
          });
        }
        res.json({ message: 'Personal message sent successfully' });
      });
    }
});


// Mark personal messages as read in a conversation
app.post('/api/personal-chat/:userId/mark-read', authenticateToken, (req, res) => {
  const otherUserId = req.params.userId;
  const currentUserId = req.user.id;
  const updateQuery = `
    UPDATE personal_messages 
    SET is_read = 1 
    WHERE receiver_id = ? AND sender_id = ? AND is_read = 0
  `;
  db.query(updateQuery, [currentUserId, otherUserId], (err) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Personal messages marked as read' });
  });
});

// Get unread personal message count for the logged-in user
app.get('/api/unread-count', authenticateToken, (req, res) => {
  const currentUserId = req.user.id;
  const countQuery = `
    SELECT COUNT(*) AS unreadCount 
    FROM personal_messages 
    WHERE receiver_id = ? AND is_read = 0
  `;
  db.query(countQuery, [currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results[0]);
  });
});


// List users who have sent messages to the current user along with unread counts
app.get('/api/personal-chats', authenticateToken, (req, res) => {
  const currentUserId = req.user.id;
  const query = `
    SELECT pm.sender_id AS user_id, u.username, SUM(IF(pm.is_read = 0, 1, 0)) AS unreadCount
    FROM personal_messages pm
    JOIN users u ON pm.sender_id = u.id
    WHERE pm.receiver_id = ?
    GROUP BY pm.sender_id, u.username
  `;
  db.query(query, [currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

// ---------------------- Posting Endpoint ----------------------

// Create a new posting with an optional image upload
app.post('/postings', authenticateToken, upload.single('listing_image'), (req, res) => {
  const {
    user_id,
    type,
    title,
    description,
    price,
    distance,
    category,
    subcategory,
    item,
    gig_coin_reward,
    questions,
    buyorsell  // new field added
  } = req.body;

  if (!type) {
    return res.status(400).send("Missing required field: type.");
  }

  let imageUrl = null;

  // Insert posting into the database
  const insertPosting = () => {
    const sql = `
      INSERT INTO postings (
        user_id, type, title, description, listing_image, price,
        distance, category, subcategory, item, gig_coin_reward, questions, buyorsell
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [
      user_id,
      type,
      title || null,
      description || null,
      imageUrl,
      price || null,
      distance || null,
      category || null,
      subcategory || null,
      item || null,
      gig_coin_reward || null,
      questions || null,
      buyorsell || null  // new field included
    ];
    db.query(sql, values, (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).send("Database insert failed.");
      }
      res.json({
        message: "Posting created successfully!",
        id: result.insertId,
        image: imageUrl
      });
    });
  };

  // If an image file is provided, upload it to Cloudinary
  if (req.file) {
    const streamUpload = (buffer) => {
      return new Promise((resolve, reject) => {
        let stream = cloudinary.uploader.upload_stream(
          { folder: 'postings' },
          (error, result) => {
            if (result) resolve(result);
            else reject(error);
          }
        );
        streamifier.createReadStream(buffer).pipe(stream);
      });
    };

    streamUpload(req.file.buffer)
      .then((result) => {
        imageUrl = result.secure_url;
        insertPosting();
      })
      .catch((error) => {
        console.error("Cloudinary upload failed:", error);
        res.status(500).json({ error: error.message });
      });
  } else {
    insertPosting();
  }
});


// ---------------------- Discussion Forum Endpoints ----------------------

// Get all forum messages
app.get('/api/forum/messages', authenticateToken, (req, res) => {
  const query = `
    SELECT fm.*, u.username 
    FROM forum_messages fm
    JOIN users u ON fm.user_id = u.id
    ORDER BY fm.created_at ASC
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

// Post a new forum message (text only)
app.post('/api/forum/messages', authenticateToken, (req, res) => {
  const { message } = req.body;
  const currentUserId = req.user.id;
  const insertQuery = `
    INSERT INTO forum_messages (user_id, message, is_read) VALUES (?, ?, 0)
  `;
  db.query(insertQuery, [currentUserId, message], (err) => {
    if (err) return res.status(500).json({ error: err });
    // Emit the new forum message to all connected users (except the sender)
    Object.keys(connectedUsers).forEach(userId => {
      if (parseInt(userId) !== currentUserId) {
        io.to(connectedUsers[userId]).emit('newForumMessage', {
          sender_id: currentUserId,
          message,
          created_at: new Date()
        });
      }
    });
    res.json({ message: 'Forum message posted successfully' });
  });
});

// Mark all forum messages as read for the current user
app.post('/api/forum/mark-read', authenticateToken, (req, res) => {
  const currentUserId = req.user.id;
  const updateQuery = `
    UPDATE forum_messages 
    SET is_read = 1 
    WHERE user_id != ? AND is_read = 0
  `;
  db.query(updateQuery, [currentUserId], (err) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Forum messages marked as read' });
  });
});

// Get the unread forum message count for the current user
app.get('/api/forum/unread-count', authenticateToken, (req, res) => {
  const currentUserId = req.user.id;
  const countQuery = `
    SELECT COUNT(*) AS unreadCount 
    FROM forum_messages 
    WHERE user_id != ? AND is_read = 0
  `;
  db.query(countQuery, [currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results[0]);
  });
});



// ============================================= Payment ==================================
app.post('/api/payment', authenticateToken, (req, res) => {
  const { amount, walletAddress , token } = req.body;

  // Validate that both amount and wallet address are provided
  if (!amount || !walletAddress || !token) {
    return res.status(400).json({ error: 'Amount and wallet address are required.' });
  }

  // Validate that the amount is a positive number
  if (isNaN(amount) || Number(amount) <= 0) {
    return res.status(400).json({ error: 'Invalid amount. Amount must be a positive number.' });
  }

  res.json({ message: 'Payment processed successfully!' });
});




// ---------------------- Transaction Endpoint ----------------------

// Process and store transaction details after a successful payment
app.post('/api/transaction', authenticateToken, (req, res) => {
  const { buyer_wallet_address, merchant_wallet_address, amount, product_name, buyer_ad_FK, token } = req.body;
  console.log(req.body);
  
  // Validate that all required fields are provided
  if (!buyer_wallet_address || !merchant_wallet_address || !amount || !product_name || !token || !buyer_ad_FK) {
    return res.status(400).json({ error: 'buyer_wallet_address, merchant_wallet_address, amount, product_name, and token are required.' });
  }

  // Validate that the amount is a positive number
  if (isNaN(amount) || Number(amount) <= 0) {
    return res.status(400).json({ error: 'Invalid amount. Amount must be a positive number.' });
  }

  const insertQuery = `
    INSERT INTO transaction (buyer_wallet_address, merchant_wallet_address, amount, product_name, buyer_ad_FK, token)
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  db.query(insertQuery, [buyer_wallet_address, merchant_wallet_address, amount, product_name, buyer_ad_FK, token], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Transaction recorded successfully!', transactionId: result.insertId });
  });
});

app.post('/api/walletconnectinsert', (req, res) => {
  const { walletaddress } = req.body;

  if (!walletaddress) {
    return res.status(400).json({ error: 'walletaddress is required' });
  }

  // 1. Check if walletaddress already exists
  const checkSql = 'SELECT * FROM walletconnect WHERE walletaddress = ?';
  db.query(checkSql, [walletaddress], (checkErr, results) => {
    if (checkErr) {
      console.error('Check error:', checkErr);
      return res.status(500).json({ error: 'Database error during check' });
    }

    if (results.length > 0) {
      // Wallet already exists, return success without inserting
      return res.status(200).json({ message: 'Wallet already exists. Skipping insert.' });
    }

    // 2. Insert if not exists
    const insertSql = 'INSERT INTO walletconnect (walletaddress) VALUES (?)';
    db.query(insertSql, [walletaddress], (insertErr, insertResult) => {
      if (insertErr) {
        console.error('Insert error:', insertErr);
        return res.status(500).json({ error: 'Database error during insert' });
      }

      res.status(201).json({ message: 'Inserted successfully' });
    });
  });
});




app.post('/api/getwalletid', (req, res) => {
  // Retrieve wallet address from the request body
  const { walletaddress } = req.body;

  // Validate that the wallet address was provided
  if (!walletaddress) {
    return res.status(400).json({ error: 'Wallet address is required.' });
  }

  // SQL query to retrieve wallet_id from wallet address
  const sql = 'SELECT wallet_id FROM walletconnect WHERE walletaddress = ?';

  // Execute the query using the database connection
  db.query(sql, [walletaddress], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    // Check if any record exists for the provided wallet address
    if (results.length === 0) {
      return res.status(404).json({ error: 'Wallet address not found.' });
    }

    // Return the wallet_id from the first matching record
    res.json({ wallet_id: results[0].wallet_id });
  });
});

// Start the server with Socket.IO
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
