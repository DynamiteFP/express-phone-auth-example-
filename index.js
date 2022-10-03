let app = require('express')();
let crypto = require('crypto');
let jwt = require('jsonwebtoken');
let bodyParser = require('body-parser');

var users = [
	{
		id: 1,
		name: 'John Doe',
		number: '+1234567890',
	},
	{
		id: 2,
		name: 'Bob Williams',
		number: '1234567891',
	},
];

//Enable body parsing
let jsonParser = bodyParser.json();

//Get the secret key from the environment variable
require('dotenv').config();
let hashKey = process.env.HASH_KEY;
let jwtKey = process.env.JWT_KEY;
var accountSid = process.env.TWILIO_ACCOUNT_SID;
var authToken = process.env.TWILIO_AUTH_TOKEN;
let twilioNumber = process.env.TWILIO_NUMBER;

//Declare client
let client = require('twilio')(accountSid, authToken);

//Endpoint to Request the OTP
app.post('/requestOtp', jsonParser, async (req, res) => {
	//Get the user number from the request body
	let number = req.body.number;

	//Otp generation logic
	let otp = Math.floor(1000 + Math.random() * 9000);

	//Create a secret hash to verify the client
	let ttl = 5 * 60 * 1000;
	let expires = Date.now() + ttl;
	let data = `${number}.${otp}.${expires}`;
	let hash = crypto.createHmac('sha256', hashKey).update(data).digest('hex');
	let secretHash = `${hash}.${expires}`;

	//Check if the user exists
	var user = users.find((user) => user.number === number);

	//Handle the case when the user does not exist
	if (!user) {
		users.push({
			id: users.length + 1,
			name: '',
			number: number,
		});
	}

	//Calling the twilio SMS API to send the OTP
	try {
		client.messages
			.create({
				body: `Dear customer,\n Your OTP is ${otp}. PLEASE DO NOT SHARE THIS OTP WITH ANYONE.`,
				from: twilioNumber,
				to: number,
			})
			.then(() => {
				//Send the secret hash to the client
				res.json(secretHash);
			})
			.catch((err) => {
				//Handle the twilio error
				res.status(500).send('Error sending OTP');
			});
	} catch (err) {
		//Handle the error
		console.log(err);
	}
});

//Endpoint to verify the OTP
app.post('/verifyOtp', jsonParser, async (req, res) => {
	//Get the user number, secret hash and otp from the request body
	let { number, otp, secretHash } = req.body;

	//Slice the hash and the expiry time from the secret hash
	let [hashValue, expires] = secretHash.split('.');

	let now = Date.now();
	//Check if the hash has expired
	//Handle the case when the hash has expired
	if (now > parseInt(expires))
		return res.json({ error: 'Timeout. Please try again' });

	//Create a new hash using the user number, otp and the expiry time
	let data = `${number}.${otp}.${expires}`;
	let newCalculatedHash = crypto
		.createHmac('sha256', hashKey)
		.update(data)
		.digest('hex');
	//Compare the new hash with the hash sent by the client
	if (newCalculatedHash === hashValue) {
		var user = users.find((user) => user.number === number);

		let payload = {
			number: number,
			name: user.name,
			id: user._id,
		};
		//Create a JWT token
		let token = jwt.sign(payload, jwtKey, { expiresIn: '1y' });

		//Send the token to the client
		return res.json(token);
	} else {
		//Handle the case when the hash does not match
		return res.json({ error: 'Invalid OTP. Please try again' });
	}
});

app.listen(3000, () => {
	console.log('Server started on port 3000');
});
