const User = require("../models/User");
const bcryptjs = require("bcryptjs");
const {
  UnauthorizedError,
  NotFoundError,
  ValidationError,
  NotImplementedError,
  BadRequestError,
} = require("../utils/errors");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const jwt = require("jsonwebtoken");
const { ROLE } = require("../config/constant");
const {
  validatePasswordStrength,
} = require("../utils/validatePasswordStrength");
const JWT_KEY = "jwtactive987";

// user login function
const verifyUserLogin = async (email, password) => {
  try {
    const user = await User.findOne({ email }).lean();
    if (!user) throw new NotFoundError("User not found");
    if (await bcryptjs.compare(password, user.password)) {
      // creating a JWT token
      token = jwt.sign({ email: user.email, role: user.role }, JWT_KEY, {
        expiresIn: "24h",
      });
      return { status: "ok", data: token };
    } else throw new ValidationError("Invalid password");
  } catch (error) {
    console.log(error);
    return { status: "error", error: "timed out" };
  }
};

exports.login = async (body) => {
  let { email, password } = body;

  let user = await User.findOne({
    email: email,
  });

  if (!user) throw new NotFoundError("User not found");
  else if (!user.verified) throw new BadRequestError("User not verify");
  // if (!(await bcryptjs.compare(password, user.password)))
  // 	throw new ValidationError('Wrong password.')

  const response = await verifyUserLogin(email, password);
  if (response.status === "ok") {
    user.password = response.data;
    return user;
  } else throw new ValidationError("Invalid password.");
};

exports.register = async (header, body) => {
  let { username, password, email } = body;

  // validating password only as email validation is being done in the userSchema itself.
  if (!validatePasswordStrength(password)) {
    throw new BadRequestError("Password is not Strong enough!.");
  }

  /* 
    nonce and wallet_password is set to be unique in UserSchema but default value is set to be null.
    but every time a user signs up the values for nonce and wallet_passwrod is set to null which violates
    the unique constraint set in UserSchema. that's why I'm setting random string for nonce and wallet_passwrod
    for the first time when user signs up.
  */

  if (!body.nonce) {
    body.nonce = await bcryptjs.hash(email, 10);
  }

  if (!body.wallet_address) {
    body.wallet_address = await bcryptjs.hash(email, 10);
  }

  if (await User.exists({ username: username, email: email }))
    throw new BadRequestError("User already exist.");

  //   let hashedPass = await bcryptjs.hash(password, 10);
  // const emailVerificationCode = uid()

  //   we're passing unhashed password as the password will automatically be saved as a hash using UserSchema.pre()
  let user = new User({
    username: username,
    password: password,
    email: email,
    role: ROLE.CUSTOMER,
    nonce: body.nonce,
    wallet_address: body.wallet_address,
  });

  await user.save();

  // Send Mail
  const oauth2Client = new OAuth2(
    "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com", // ClientID
    "OKXIYR14wBB_zumf30EC__iJ", // Client Secret
    "https://developers.google.com/oauthplayground" // Redirect URL
  );

  oauth2Client.setCredentials({
    refresh_token:
      "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
  });
  const accessToken = oauth2Client.getAccessToken();

  const token = jwt.sign(
    { username, email, password, role: ROLE.CUSTOMER },
    JWT_KEY,
    { expiresIn: "24h" }
  );
  const CLIENT_URL = "http://" + header.host;

  console.log(token, CLIENT_URL);
  const output = `
    <h2>Please click on below link to activate your account</h2>
    <a href=${CLIENT_URL}/auth/verify/${token}>Verify Email</a>
    <p><b>NOTE: </b> The above activation link expires in 30 minutes.</p>
    `;

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: "nodejsa@gmail.com",
      clientId:
        "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com",
      clientSecret: "OKXIYR14wBB_zumf30EC__iJ",
      refreshToken:
        "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
      accessToken: accessToken,
    },
  });

  // send mail with defined transport object
  const mailOptions = {
    from: "<nodejsa@gmail.com>", // sender address
    to: email, // list of receivers
    subject: "Account Verification: OASIS Nyxcipher Auth", // Subject line
    generateTextFromHTML: true,
    html: output, // html body
  };

  await transporter.sendMail(mailOptions);

  return user;
};

exports.verify = async (params) => {
  const { token } = params;
  if (!token)
    throw new UnauthorizedError("Email not verify! Please write password.");
  const decodeToken = jwt.verify(token, JWT_KEY);
  if (!decodeToken)
    throw new UnauthorizedError(
      "Incorrect or expired link! Please register again."
    );

  const { email } = decodeToken;
  let user = await User.findOne({ email: email });
  if (user.verified) throw new UnauthorizedError("Email already verified.");

  user.verified = true;
  await user.save();
  return user;
};

exports.reset = async (body) => {
  let { password, email } = body;
  let user = await User.findOne({
    email: email,
  });

  if (!validatePasswordStrength(password)) {
    throw new BadRequestError("Password is not Strong enough!.");
  }

  if (!user) throw new NotFoundError("User already exist.");
  //   let hashedPass = await bcryptjs.hash(password, 10);

  // now the password will get hashed automatically with preSave feature in UserSchema
  user.password = password;

  await user.save();

  return user;
};

exports.forgot = async (req) => {
  const { email } = req.body;

  if (!email) throw new ValidationError("Please enter an email ID");

  let user = await User.findOne({ email: email });

  if (!user) throw new NotFoundError("User with Email ID does not exist!");

  const oauth2Client = new OAuth2(
    "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com", // ClientID
    "OKXIYR14wBB_zumf30EC__iJ", // Client Secret
    "https://developers.google.com/oauthplayground" // Redirect URL
  );

  oauth2Client.setCredentials({
    refresh_token:
      "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
  });
  const accessToken = oauth2Client.getAccessToken();

  const token = jwt.sign({ _id: user._id }, JWT_KEY, { expiresIn: "24h" });
  const CLIENT_URL = "http://" + req.headers.host;
  const output = `
    <h2>Please click on below link to reset your account password</h2>
    <a herf={${CLIENT_URL}/auth/forgot/${token}}>${CLIENT_URL}/auth/forgot/${token}</a>
    <p><b>NOTE: </b> The activation link expires in 30 minutes.</p>
    `;

  const updateUser = User.updateOne({ resetLink: token });
  if (!updateUser) throw new BadRequestError("Error resetting password!");

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: "nodejsa@gmail.com",
      clientId:
        "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com",
      clientSecret: "OKXIYR14wBB_zumf30EC__iJ",
      refreshToken:
        "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
      accessToken: accessToken,
    },
  });

  // send mail with defined transport object
  const mailOptions = {
    from: '"Auth Admin" <nodejsa@gmail.com>', // sender address
    to: email, // list of receivers
    subject: "Account Password Reset: OASIS Auth ✔", // Subject line
    html: output, // html body
  };

  const sendMail = transporter.sendMail(mailOptions);
  if (!sendMail)
    throw new NotImplementedError(
      "Something went wrong on our end. Please try again later."
    );

  return sendMail;
};
