const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');


const app = express();
const PORT = 3000;
const JWT_SECRET = 'temp_scretkeyyyy2222'; // Use a secure key in production
mongoose.connect('mongodb://localhost/heatmapDB', { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
});


// Middleware
app.use(express.json());
app.use(express.static('public'))
// Connect to MongoDB

// Event Schema
const eventSchema = new mongoose.Schema({
    title: { type: String, required: true },
    date: { type: Date, required: true },
    description: { type: String }
  });
  
  // Calendar Schema
  const calendarSchema = new mongoose.Schema({
    name: { type: String, required: true },
    events: [eventSchema] // Array of eventSchema
  });
  
// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  calendars: [calendarSchema] // Array of calendars
});

const User = mongoose.model('User', userSchema);

// Signup route
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      username,
      email,
      password: hashedPassword,
      calendars: [
        {
            name: 'Programming',
            events: [
                {title: "today", date: new Date(), description: "yoooooo"},
                {title: "tomorrow", date: new Date(), description: "yuuuuu2222"}

            ]
        },
        {
            name: 'Notprogramming',
            events: [
                {title: "today", date: new Date(), description: "yoooooo"},
                {title: "tomorrow", date: new Date(), description: "yuuuuu2222"}

            ]
        }
      ]
    });

    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  
  const { username, password } = req.body;

    try {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
      console.log(user._id)
      res.json({ token });
    
    } catch (err) {
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// Middleware to authenticate using JWT
const authenticateToken = (req, res, next) => {
    console.log('Headers:', req.headers); // Log all headers
    const authHeader = req.headers['authorization'];
    console.log('Auth Header:', authHeader); // Log the authorization header

    if (!authHeader) {
        return res.status(401).json({ error: 'No authorization header' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('JWT Verification Error:', err);
            return res.status(403).json({ error: 'Invalid token', details: err.message });
        }
        req.userId = decoded.userId;
        next();
    });
  };
  
// createCalendar route
app.post('/api/createCalendar', authenticateToken, async (req, res) => {
    try {
        const userId = req.userId;
        const { calendarName } = req.body;
  
        if (!calendarName) {
            return res.status(400).json({ error: 'Calendar name is required' });
        }
        // Find the user by ID and update their calendars
        const user = await User.findById(userId);
        if (!user) {
           return res.status(404).json({ error: 'User not found' });
        }
        user.calendars.push({ name: calendarName, events: [] });
        await user.save();
        res.status(201).json({ message: 'Calendar created successfully', calendar: user.calendars });
      } catch (err) {
            console.error('Error in createCalendar:', err);
            res.status(500).json({ error: 'Server error', details: err.message });
      }
    }
  );

// deleteCalendar route
app.post('/api/deleteCalendar', authenticateToken, async (req, res) => {
    try {
        const userId = req.userId;
        const { deleteCalendarName } = req.body;
  
        if (!deleteCalendarName) {
            return res.status(400).json({ error: 'Calendar name is required' });
        }
        // Find the user by ID and update their calendars
        const user = await User.findById(userId);
        if (!user) {
           return res.status(404).json({ error: 'User not found' });
        }
        // Find the index of the calendar with the specified name
        const calendarIndex = user.calendars.findIndex(calendar => calendar.name === deleteCalendarName);

               // Logging for debugging
               console.log('User calendars:', deleteCalendarName);
               console.log('Delete calendar name:', user.calendars[calendarIndex].name);

        if (calendarIndex === -1) {
            return res.status(404).json({ error: 'Calendar not found' });
        }
        // Remove the calendar from the array
        user.calendars.splice(calendarIndex, 1);
        await user.save();
        res.status(200).json({ message: 'Calendar deleted successfully' });
      } catch (err) {
            console.error('Error in createCalendar:', err);
            res.status(500).json({ error: 'Server error', details: err.message });
      }
    }
  );

  app.get('/api/getCalendars', authenticateToken, async (req, res) => {
    try {
        const userId = req.userId;
        // Find the user by ID and update their calendars
        const user = await User.findById(userId);
        if (!user) {
           return res.status(404).json({ error: 'User not found' });
        }
        // Respond with the user's calendars
        res.status(200).json({ calendars: user.calendars });
    } catch (err) {
        console.error('Error in getting calendars:', err);
        res.status(500).json({ error: 'Server error', details: err.message });
    }
  });

  app.post('/api/addEvent', authenticateToken, async (req, res) => {
    try {
        const userId = req.userId;
        const { calendarName, event } = req.body;
        
        if (!calendarName || !event) {
            return res.status(400).json({ error: 'Missing required field.' });
        }

        // Find the user by ID and update their calendars
        const user = await User.findById(userId);
        if (!user) {
           return res.status(404).json({ error: 'User not found' });
        }

        // Find the index of the calendar with the specified name
        const calendarIndex = user.calendars.findIndex(calendar => calendar.name === calendarName);
        if (calendarIndex === -1) {
            return res.status(404).json({ error: 'Calendar not found' });
        }

        // Add the new event to the calendar's events array
        calendar.events.push(event);
        await user.save();
        res.status(200).json({ message: 'Event inserted successfully' });
    } catch (err) {
        console.error('Error in addEvent:', err);
        res.status(500).json({ error: 'Server error', details: err.message });
    }
  }
);



app.listen(PORT, () => console.log(`Server running on port ${PORT}`));