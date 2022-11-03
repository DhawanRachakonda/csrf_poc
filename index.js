const { csrfSync } = require("csrf-sync");
const express = require("express");
const session = require("express-session");
var cors = require('cors');
const cookieParser = require('cookie-parser');
const Crypto = require('crypto');
const ngrok = require('ngrok');

const app = express();
const port = 5555;

app.set('view engine','ejs')

const oneDay = 1000 * 60 * 60 * 24;
app.use(
    session({
      // Don't do this, use a cryptographically random generated string
      secret: Crypto
      .randomBytes(21)
      .toString('base64')
      .slice(0, 21),
      saveUninitialized:true,
      cookie: { maxAge: oneDay },
      resave: false
    })
);

app.use(cookieParser());

app.use(cors({
  origin: ['http://localhost:3000'],
  methods: ['GET','POST','DELETE','UPDATE','PUT','PATCH']
}));

const getTokenFromState = (req) => {
    console.log("Getting token in state ", req.session.csrfToken);
  return req.session.csrfToken;
}

const isRequestValid = (req) => {
    const receivedToken = req.cookies["X-csrf-token"];
    const storedToken = getTokenFromState(req);
    console.log("Received Token : ", receivedToken);
    return (typeof receivedToken === "string" &&
        typeof storedToken === "string" &&
        receivedToken === storedToken);
};

const csrfSynchronisedProtection = (req, res, next) => {
    const isCsrfValid = isRequestValid(req);
    if (!isCsrfValid) {
        return next(invalidCsrfTokenError);
    }
    next();
}

const { generateToken, revokeToken, invalidCsrfTokenError }  = csrfSync({
    getTokenFromState, // Used to retrieve the token from state.
    storeTokenInState : (req, token) => {
        console.log("Storing token in state ", token);
      req.session.csrfToken = token;
    }, // Used to store the token in state.
    size : 128, // The size of the generated tokens in bits
    csrfSynchronisedProtection,
  });

app.get("/csrf-token", (req, res) => {
    const token = generateToken(req);
    res.cookie('X-csrf-token',token, { maxAge: 900000, httpOnly: true, secure: true, sameSite: "strict"});
  return res.render('index', {csrfToken: token});
});

app.get("/hello", (req, res) => {
  return res.send("Hello World!");
});

const myProtectedRoute = (req, res) =>
  res.json({ unpopularOpinion: "Game of Thrones was amazing" });

app.post("/secret-stuff", csrfSynchronisedProtection, myProtectedRoute);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
  (async function() {
    const url = await ngrok.connect(port);
    console.log("URL => ", url);
  })();
});