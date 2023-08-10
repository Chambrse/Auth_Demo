const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const path = require('path');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

mongoose.connect('mongodb+srv://SERVER_USER:Re9YcJ0QYDZoa5R8@cluster0.qonwhtd.mongodb.net/?retryWrites=true&w=majority', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

mongoose.connection.once('open', () => {
    console.log('Connected to MongoDB');
});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    // any other fields you want to include
});

userSchema.pre('save', function (next) {
    const user = this;

    if (!user.isModified('password')) {
        return next();
    }

    bcrypt.genSalt(10, (err, salt) => {
        if (err) {
            return next(err);
        }
        bcrypt.hash(user.password, salt, (err, hash) => {
            if (err) {
                return next(err);
            }
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function (candidatePassword) {
    const user = this;
    return new Promise((resolve, reject) => {
        bcrypt.compare(candidatePassword, user.password, (err, isMatch) => {
            if (err) {
                return reject(err);
            }
            if (!isMatch) {
                return reject(false);
            }
            resolve(true);
        });
    });
};

const User = mongoose.model('User', userSchema);

passport.use(new LocalStrategy(
    function (username, password, done) {
        console.log('LocalStrategy');
        User.findOne({ username: username }).then((user) => {
            // if (err) { return done(err); }
            if (!user) { return done(null, false); }
            user.comparePassword(password).then(isMatch => {
                if (isMatch) {
                    return done(null, user);
                } else {
                    return done(null, false);
                }
            }).catch(err => {
                return done(err);
            });
            // return done(null, user);
        }).catch((err) => {
            return done(err);
        });

    }
));

passport.use(new GoogleStrategy({
    clientID: '455419890686-86p7261h9ujgc92dejgmuth7dm8s2mv9.apps.googleusercontent.com', // Replace with your client ID from Google Developer Console
    clientSecret: 'MPFSAnRFUC_zC0utyWfuo2Av', // Replace with your client secret from Google Developer Console
    callbackURL: "https://auth-demo-budd-d853cd15782f.herokuapp.com/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    profile.source = 'google';
    return done(null, profile);
  }
));

// passport.serializeUser(function (user, done) {
//     done(null, user.id);
// });

// passport.deserializeUser(function (id, done) {
//     User.findById(id).then((user) => {
//         done(null, user);
//     }).catch((err) => {
//         done(err, null);
//     });
// });

passport.serializeUser(function(user, done) {
    done(null, { id: user.id, source: user.source }); // Add the source
  });

passport.deserializeUser(function(obj, done) {
    if (obj.source === 'google') {
      // Handle Google user
      done(null, obj);
    } else {
      // Handle local user
      User.findById(obj.id).then((user) => {
          done(null, user);
      }).catch((err) => {
          done(err, null);
      });
    }
  });

// Create a session store in MongoDB
// const store = new MongoDBStore({
//     uri: 'mongodb://localhost/mydatabase',
//     collection: 'sessions'
// });

const store = new MongoDBStore({
    uri: 'mongodb+srv://SERVER_USER:Re9YcJ0QYDZoa5R8@cluster0.qonwhtd.mongodb.net/?retryWrites=true&w=majority',
    collection: 'sessions'
});

// Parse JSON request bodies
app.use(express.json());

// Parse URL-encoded request bodies
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'some secret',
    resave: false,
    saveUninitialized: false,
    store: store
}));

app.use(passport.initialize());
app.use(passport.session());

// set public folder
app.use(express.static(path.join(__dirname, 'public')));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful login
    console.log('Successful login');
    res.redirect('/');
  });

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}), (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    } else {
        return res.redirect('/login');
    }
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Missing username or password');
    }

    try {
        const existingUser = await User.findOne({ username });

        if (existingUser) {
            return res.status(400).send('User already exists');
        }

        const user = new User({ username, password });
        await user.save();

        req.login(user, function (err) {
            if (err) {
                return res.status(500).send(err);
            }
            return res.redirect('/');
        });

    } catch (error) {
        return res.status(500).send('Error signing up user');
    }
});

app.get('/logout', (req, res) => {
    console.log('Logging out');
    req.logout((err) => {
        if (err) {
            throw err;
        }
    });
    res.redirect('/login'); // You can redirect wherever you want after logout
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        // The user is authenticated, proceed to the next middleware function or route handler
        return next();
    }
    // The user is not authenticated, redirect them to the login page
    res.redirect('/login');
}
// The rest of your routes go here
app.get('/', ensureAuthenticated, function (req, res) {
    res.sendFile(path.join(__dirname, 'success.html'));
});

app.get('/login', function (req, res) {
    res.sendFile(path.join(__dirname, 'login.html'));
});

const port = process.env.PORT || 3000;


app.listen(port, () => console.log('Server started on port 3000'));