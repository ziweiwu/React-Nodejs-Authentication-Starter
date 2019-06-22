const jwt = require('jwt-simple');
const User = require('../models/user.js');
const config = require('../config');

// jwt has a sub property about whose token is for
// iat is what time the token is created
function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  // User has already had their email and password auth'd
  // We just need to give them a token
  res.send({ token: tokenForUser(req.user) });
};

exports.signup = function(req, res, next) {
  const { email } = req.body;
  const { password } = req.body;

  // if user does not provide all fields

  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide an email and a password' });
  }

  // see if a user with the given email exists
  User.findOne({ email }, (err, existingUser) => {
    if (err) {
      return next(err);
    }

    // if a user with email does exist, return an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use' });
    }

    // if a user with email does not exist, create and save user record
    const user = new User({
      email,
      password
    });

    user.save(() => {
      if (err) {
        return next(err);
      }

      // respond to request indicating the user was created
      res.json({ token: tokenForUser(user) });
    });
  });

  return res.status(200);
};
