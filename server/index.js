// !What is JWT and why??????

/*

* json web token
* when we first connect  to our server create a JWT and send that to us.
* We save that to us . We save that in browser storage and send that to server in subsequent request.
* Server each time compares the jwt and verifies.

? Server is not saving the jwt in it but in session it is saving it in server.

* In cookies the session is saved in server and the cookie i send to client
* Here the server need to save the session (session id)

? Jwt is also used in cases there is many micro-server.

* session and cookies need to be saved in the server so if multiple serves are involved then each server need to authenticate the session id saved.

*/

const express = require('express');
var jwt = require('jsonwebtoken');
const app = express();

const users = [
	{ id: '1', username: 'manu', password: 'panu123', isAdmin: true },
	{ id: '2', username: 'mithun', password: 'mithun123', isAdmin: false },
];

app.use(express.json());

let refreshTokenArray = [];

// ! function to generate access token
const generateAccessToken = (user) => {
	return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'mySecretKey', {
		expiresIn: '15m',
	});
};

// ! function to generate refresh token
const generateRefreshToken = (user) => {
	return jwt.sign(
		{ id: user.id, isAdmin: user.isAdmin },
		'myRefreshTokenSecretKey',
	);
};

// ! middleware to verify token
const verify = (req, res, next) => {
	const authHeader = req.headers.authorization;
	console.log(authHeader);
	if (authHeader) {
		const token = authHeader.split(' ')[1];

		jwt.verify(token, 'mySecretKey', (error, user) => {
			if (error) {
				return res.status(403).json('Token not valid');
			}

			req.user = user;
			next();
		});
	} else {
		res.status(401).json('you are not authenticated');
	}
};

// * login route

app.post('/login', function (req, res) {
	const { username, password } = req.body;
	const user = users.find((u) => {
		return u.username === username && u.password === password;
	});
	if (user) {
		// generate a access token
		const accessToken = generateAccessToken(user);
		// generate a refresh token
		const refreshToken = generateRefreshToken(user);
		refreshTokenArray.push(refreshToken);
		// we can give expires time like this as m, s , h etc
		res.status(200).json({ user: username, token: accessToken, refreshToken });
	} else {
		res.status(400).json('uSERNAME OR PASSWORD INCORRECT!');
	}
});

// * refresh token route

app.post('/refresh', (req, res) => {
	// take the refresh token from users
	const refreshToken = req.body.token;

	// send error if this is no token or its invalid
	if (!refreshToken) return res.send(401).json('you are not authenticated!');
	if (!refreshTokenArray.includes(refreshToken))
		return res.status(401).json('Refrsh token not valid');

	// if everything is ok , create new access token , refresh token and send to user
	jwt.verify(refreshToken, 'myRefreshTokenSecretKey', (error, user) => {
		error && console.log(error);
		refreshTokenArray = refreshTokenArray.filter(
			(token) => token !== refreshToken,
		);

		const newAccessToken = generateAccessToken(user);
		const newRefreshToken = generateRefreshToken(user);

		refreshTokenArray.push(newRefreshToken);

		res
			.status(200)
			.json({ refreshToken: newRefreshToken, accessToken: newAccessToken });
	});
});

// * delete token route

app.delete('/users/:userId', verify, (req, res) => {
	if (req.user.id === req.params.userId || req.user.isAdmin) {
		res.status(200).json('User has been deleted');
	} else {
		res.status(403).json('You are not allowed to delete this user');
	}
});

// * logout route

app.post('/logout', verify, (req, res) => {
	const refreshToken = req.body.token;
	refreshTokenArray.filter((token) => token !== refreshToken);

	res.status(200).json('User has been logged out');
});

app.listen(5001, () => {
	console.log('Server running at portnumber 5001');
});
