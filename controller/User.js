const express = require('express');
const {reg} = require('../model/registration');
const BankDetails =require('../model/bankdetails');
const router = express.Router();
const { Op, where } = require("sequelize");
const axios = require('axios');
const Country =require('../model/country');
const session = require('express-session');
const Redis = require('ioredis');
const redis = new Redis();
const questions =require("../model/question");
const {Users,sequelize} = require('../model/validUsers');
const Meditation =require('../model/meditation');
const moment = require('moment');
const bcrypt = require('bcrypt');
const timeTracking = require('../model/timeTracking');
const Messages = require('../model/message');
const Appointment = require("../model/appointment");
const nodemailer = require('nodemailer');
const meditation = require('../model/meditation');
const message = require('../model/message');
const Broadcast = require('../model/broadcast');
const applicationconfig = require('../model/applicationConfig');
const multer = require('multer');
const admin = require('firebase-admin');
const serviceAccount = require("../serviceAccountKey.json");
const { AwsInstance } = require('twilio/lib/rest/accounts/v1/credential/aws');
const storage = admin.storage().bucket();
// Multer configuration for handling file uploads
const upload = multer({ dest: 'uploads/' });
const privateMsg = require('../model/privateMsg');
const operatorMsg = require('../model/operatorMsg');
const GroupMembers = require('../model/groupmembers');

/**
 * @swagger
 * components:
 *   schemas:
 *     UserUpdate:
 *       type: object
 *       properties:
 *         first_name:
 *           type: string
 *         last_name:
 *           type: string
 *         DOB:
 *           type: string
 *         gender:
 *           type: string
 *         email:
 *           type: string
 *         address:
 *           type: string
 *         pincode:
 *           type: integer
 *         state:
 *           type: string
 *         district:
 *           type: string
 *         country:
 *           type: string
 *         phone:
 *           type: string
 *         reference :
 *           type: string
 *         languages:
 *           type: string
 *         remark:
 *           type: string
 *         verify:
 *           type: string
 *         userId :
 *           type: integer
 *         DOJ:
 *           type: string 
 *         password:
 *           type: string
 *         classAttended:
 *           type: string
 *         createdAt :
 *           type: string
 *         updatedAt:
 *           type: string
 *     BankDetails:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *         AadarNo:
 *           type: string
 *         IFSCCode:
 *           type: string
 *         branchName:
 *           type: string
 *         accountName:
 *           type: string
 *         accountNo:
 *           type: string
 *         createdAt :
 *           type: string
 *         updatedAt:
 *           type: string
 *         regId:
 *           type: integer
 */

router.get('/getAllUsers', async (req, res) => {
  try {
    // Fetch all users from the reg table
    const users = await reg.findAll();

    // Map users to include profilePicUrl field
    const usersWithProfilePicUrl = await Promise.all(users.map(async user => {
      let profilePicUrl = null;
      if (user.profilePicUrl) {
        // If profilePicUrl exists, fetch the image URL from Firebase Storage
        const file = storage.file(user.profilePicUrl.split(storage.name + '/')[1]);
        const [exists] = await file.exists();
        if (exists) {
          profilePicUrl = await file.getSignedUrl({
            action: 'read',
            expires: '03-01-2500' // Adjust expiration date as needed
          });
        }
      }
      // Return user details with profilePicUrl
      return {
        ...user.toJSON(),
        profilePicUrl
      };
    }));

    // Send the response with users data including profilePicUrl
    return res.status(200).json({ users: usersWithProfilePicUrl });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/countries', async (req, res) => {
    const data = req.body; // Assuming req.body is an array of objects

    if (Array.isArray(data)) {
        try {
            // Use Sequelize to bulk create the data in the database
            await Country.bulkCreate(data);

            res.status(200).send({ message: "Countries added to the database successfully" });
        } catch (error) {
            console.error(error);
            res.status(500).send({ message: "An error occurred while adding countries to the database" });
        }
    } else {
        res.status(400).send({ message: "Invalid data format. Please send an array of objects." });
    }
});

router.get('/countrieslist', async (req, res) => {
    try {
      const countries = await Country.findAll({
        order: [['name', 'ASC']], // Order by the 'name' field in ascending order
      });
  
      res.json(countries);
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: 'An error occurred while fetching countries' });
    }
  });
  
router.post('/registerUser', async (req, res) => {
    const { email, phone } = req.body;

    try {
        const existingUser = await reg.findOne({
            where: {
                [Op.or]: [
                    { email: email },
                    { phone: phone }
                ]
            }
        });

        if (existingUser) {

            if (existingUser.email === email) {
                return res.status(400).json({ message: "Email already exists" , status:'false',flag :'email'});
            } else {
                return res.status(400).json({ message: "Phone number already exists",status:'false',flag :'phone' });
            }
        } 
        else{
            return res.status(200).json({ message: "OTP sent successfully" });
        }
    } catch (error) {
        console.error("Error registering user:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
});

function generateOTP() {
    // Generate a random 4-digit OTP
    return Math.floor(1000 + Math.random() * 9000).toString();
}

router.get('/displayDataFromRedis/:key', async (req, res) => {
    const key = req.params.key;

    try {
        // Retrieve data from Redis using the provided key
        const data = await redis.get(key);

        if (data) {
            // If data exists, parse it and send it in the response
            const parsedData = JSON.parse(data);
            res.status(200).json(parsedData);
        } else {
            res.status(404).json({ message: 'Data not found in Redis' });
        }
    } catch (error) {
        console.error('Error retrieving data from Redis:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});
router.post("/verify_otp", async (req, res) => {
  console.log("<........verify OTP user........>");
  try {
    const { first_name, last_name, email, DOB, gender, country, phone, reference, languages, remark, OTP } = req.body;

    console.log("Phone: " + phone);
    console.log("OTP: " + OTP);
    const storedOTP = "1111";
    console.log(first_name, last_name, email, DOB, gender, country, phone, reference, languages, remark, OTP, storedOTP);

    if (storedOTP == OTP) {
      console.log(".......");

      const hashedPassword = await bcrypt.hash(phone, 10);
      const maxUserId = await reg.max('UId');
      const UId = maxUserId + 1;
      const currentDate = new Date().toJSON().split('T')[0]; // Get the current date in "YYYY-MM-DD" format
console.log("..................currentDate.",currentDate)
      const user = await reg.create({
        first_name,
        last_name,
        email,
        DOB,
        gender,
        phone,
        country,
        reference,
        languages,
        remark,
        UId,
        DOJ: currentDate, // Set only the date portion
        expiredDate: calculateExpirationDate(),
        password: hashedPassword, // Store the hashed password
        verify: 'true'
      });

   
            // console.log("UIds.dataValues.UId",[0].reg);
       
   // })();

      // Create a record in the BankDetails table
      await BankDetails.create({
        AadarNo: "",
        IFSCCode: "",
        branchName: "",
        accountName: "",
        accountNo: "",
        UId: user.UId // Assuming regId is the foreign key in BankDetails
      });

      const responseData = {
        message: "Success",
        data: {
          id: user.UserId,
          first_name: user.first_name,
          last_name: user.last_name,
          DOJ: user.DOJ, // The stored date without the time component
          expiredDate: user.expiredDate,
          UId: user.UId 
        }
      };

      return res.status(200).json(responseData);
    } else {
      // Respond with an error message if OTP is invalid
      return res.status(400).send("Invalid OTP");
    }
  } catch (err) {
    console.error("<........error........>", err);
    return res.status(500).send(err.message || "An error occurred during OTP verification");
  }
});

function calculateExpirationDate() {
    const d = new Date();
    d.setFullYear(d.getFullYear() + 5);
    return d;
}
router.get('/listName/:UId', async (req, res) => {
  try {
      const { UId } = req.params;

      // Find the member with the provided id
      const selectedMember = await reg.findByPk(UId);

      if (!selectedMember) {
          return res.status(404).json({ error: 'Member not found' });
      }

      // Fetch the next 4 members including the selected member based on the id in ascending order
      const members = await reg.findAll({
          where: {
            UId: {
                  [Op.gte]: selectedMember.UserId, // Greater than or equal to the selected member's id
              },
          },
          order: [['UId', 'DESC']], 
          limit: 5, 
          attributes: ['first_name', 'last_name'], 
      });

      const processedData = members.map(user => ({
          name: `${user.first_name} ${user.last_name}`,
      }));

      res.status(200).json(processedData);
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred' });
  }
});

/////////////////////////////////// USER APP \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

/////////////////////////////// Request password reset/////////////////////////

/**
 * @swagger
 * /User/requestPasswordReset:
 *   post:
 *     summary: Used to reset the password
 *     description: Used to reset the password
 *     tags:
 *       - User
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The user's email address.
 *                 example: user@example.com
 *             required:
 *               - email
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal Server Error
 */

router.post('/requestPasswordReset', async (req, res) => {
    const { email } = req.body;

    try {
        // Find the user with the provided email
        const user = await reg.findOne({ where: { email: email } });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        } else {
        // // User does not exist, generate a new OTP
        // const otp = generateOTP();

        // // Save the OTP in Redis with a key that includes the user's phone number
        // const redisKey = `reqotp:${user.phone}`;
        // await redis.setex(redisKey, 600, otp);

        // // Send OTP to the user via SMS
        // const otpRequest = {
        //     method: 'get',
        //     url: `https://www.fast2sms.com/dev/bulkV2?authorization=aKVbUigWHc8CBXFA9rRQ17YjD4xhz5ovJGd6Ite3k0mnSNuZPMolFREdzJGqw8YVAD7HU1OatPTS6uiK&variables_values=${otp}&route=otp&numbers=${user.phone}`,
        //     headers: {
        //         Accept: 'application/json'
        //     }
        // };

        // await axios(otpRequest);

        return res.status(200).json({ message: "OTP sent successfully"});
    }
} catch (error) {
    console.error("Error registering user:", error);
    return res.status(500).json({ message: "Internal Server Error" });
}
});

////////////////////////////// verify-userotp ///////////////////////////////

/**
 * @swagger
 * /User/verify-userotp:
 *   post:
 *     summary: To verify the OTP
 *     description: To verify the OTP
 *     tags:
 *       - User
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               otp:
 *                 type: string 
 *             required:
 *               - email
 *               - otp
 *     responses:
 *       200:
 *         description: OTP verified successfully
 *       404:
 *         description: User not found
 *       400:
 *         description: Invalid OTP
 *       500:
 *         description: Internal Server Error
 */

router.post('/verify-userotp', async (req, res) => {
  try {
    const { otp,email } = req.body;
    const regUser = await reg.findOne({ where: { email: email } });

    if (!regUser) {
        return res.status(404).json({ message: "User not found" });
    }
    const storedOTP = "1234"; // This is just an example, replace it with the actual stored OTP

    if (storedOTP === otp) {
      return res.status(200).json({ message: 'OTP verified successfully' });
    } else {
      return res.status(400).json({ error: 'Invalid OTP' });
    }
  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

//////////////////////////////Reset password ///////////////////////////////

/**
 * @swagger
 * /User/resetPassword:
 *   post:
 *     summary: To verify the OTP
 *     description: To verify the OTP
 *     tags:
 *       - User
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               new_password:
 *                 type: string 
 *             required:
 *               - email
 *               - new_password
 *     responses:
 *       200:
 *         description: Password reset successfully
 *       404:
 *         description: User not found
 *       500:
 *         description: An error occurred during password reset
 */


router.post('/resetPassword', async (req, res) => {
  const { email, new_password } = req.body;

  try {
      // Find the user with the provided email in the 'reg' schema
      const regUser = await reg.findOne({ where: { email: email } });

      if (!regUser) {
          return res.status(404).json({ message: "User not found" });
      }

      //const storedOTP = "1234";
      // if (storedOTP === otp) {
          const hashedPassword = await bcrypt.hash(new_password, 10);

          // Update password and set classAttended to true in the 'reg' table
          await reg.update({
              password: hashedPassword,
              classAttended: true,
          }, {
              where: { email: regUser.email },
          });


          return res.status(200).json({ message: "Password reset successfully" });
     // } else {
          // Respond with an error message if OTP is invalid
          return res.status(400).json({message:"Invalid OTP"});
     // }
  } catch (err) {
      console.error("Error resetting password:", err);
      return res.status(500).send(err.message || "An error occurred during password reset");
  }
});

  /////////////////////////////////// Login ////////////////////////

  /**
 * @swagger
 * /User/login:
 *   post:
 *     summary: Login to the system
 *     description: Use this route to authenticate a user.
 *     tags:
 *       - User
 *     requestBody:
 *       description: User credentials
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: User's email
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 description: User's password
 *                 example: password123
 *     responses:
 *       '200':
 *         description: Successful login
 *         content:
 *           application/json:
 *             example:
 *               message: Login successful
 *               user:
 *                 UserId: 123
 *                 email: user@example.com
 *                 first_name: John
 *                 last_name: Doe
 *                 UId: abc123
 *                 DOJ: 2024-02-26
 *                 expiredDate: 2024-03-26
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             example:
 *               message: Email and password are required
 *       '401':
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid user or Incorrect password
 *       '404':
 *         description: Not Found
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid email
 *       '500':
 *         description: Internal Server Error
 *         content:
 *           application/json:
 *             example:
 *               message: Internal server error
 */


const sessionMiddleware = session({
    secret: '8be00e304a7ab94f27b5e5172cc0f3b2c575e87d',
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  });
  
  router.use(sessionMiddleware);

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    // Validate email and password
  
    
  if (!email || !password) {
      return res.status(400).json({ message:'Email and password are required' });
    }
  
    try {
        
      const validUser = await reg.findOne({ where: {email},
        })

        if(!validUser){
          res.status(401).json({message:"sorry ! you are not Registered"})
        }

        const user = await reg.findOne({
            where: {
                email: email,
                classAttended: true, // Check if classAttended is true
            },
        });
      if (!user) {
        return res.status(404).json({ message: 'Invalid email !' });
      }
  
      const isPasswordValid = await bcrypt.compare(password, user.password);
  
      if (!isPasswordValid) {
        return res.status(400).json({ message: 'Incorrect password !' });
      }
      // Create session and store user ID
      req.session.UId = user.UId;
      //xconsole.log(res)
      res.json({
        message: 'Login successful',
        user: {
          UserId: user.UserId,
          email: user.email,
          first_name: user.first_name,
          last_name : user.last_name,
          UId : user.UId,
          DOJ : user.DOJ,
          expiredDate :user.expiredDate
          // Don't send sensitive information like password
        },
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });

  //////////////////////////////// Hero Card ///////////////////

/**
 * @swagger
 * /User/user-details:
 *   get:
 *     summary: Get the information about the user display in profile card
 *     description: Get the home page user information 
 *     tags:
 *       - User
 *     responses:
 *       200:
 *         description: A JSON object with user details
 *         content:
 *           application/json:
 *             example:
 *               first_name: John
 *               last_name: Doe
 *               userId: 123
 *               DOJ: '2022-01-01'
 *               expiredDate: '2022-12-31'
 *       401:
 *         description: User not authenticated
 *         content:
 *           application/json:
 *             example:
 *               error: User not authenticated
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               error: User not found
 *       500:
 *         description: Internal Server Error
 *         content:
 *           application/json:
 *             example:
 *               error: Internal Server Error
 */


router.get('/user-details', async (req, res) => {
  try {
      const { UId } = req.session;
//const UId = req.body.UId;
//console.log('UId:', UId);
      if (!UId) {
          return res.status(401).json({ error: 'User not authenticated' });
      }

      const user = await reg.findOne({
          attributes: ['first_name', 'last_name', 'UId', 'DOJ', 'expiredDate'],
          where: { UId },
      });

      if (!user) {
          return res.status(404).json({ error: 'User not found' });
      }

      return res.status(200).json(user);
  } catch (error) {
      console.error('Error:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
  }
});

  //////////////////////////////// List Questions //////////////////////


/**
   * @swagger
   * /User/list-questions:
   *   get:
   *     summary: Get a list of questions from the database
   *     description: Retrieve all questions from the database
   *     tags:
 *       - User
   *     responses:
   *       200:
   *         description: A JSON array of questions
   *         content:
   *           application/json:
   *             example:
   *               - id: 1
   *                 text: "What is your name?"
   *               - id: 2
   *                 text: "How are you?"
   *       500:
   *         description: Internal Server Error
   *         content:
   *           application/json:
   *             example:
   *               message: Internal Server Error
   */


router.get('/list-questions', async (req, res) => {
  try {
    const Questions = await questions.findAll();
    res.json(Questions);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

//////////////////////////////// Appointment ///////////////////////

/**
 * @swagger
 * /User/appointment:
 *   post:
 *     summary: Create a new appointment
 *     description: Endpoint to create a new appointment
 *     tags:
 *       - Appointments
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               appointmentDate:
 *                 type: string
 *                 format: date
 *                 description: The date of the appointment
 *               num_of_people:
 *                 type: integer
 *                 description: The number of people attending the appointment
 *               pickup:
 *                 type: boolean
 *                 description: true/false
 *               room:
 *                 type: string
 *                 description: Room for the stay in the ashram
 *               from:
 *                 type: string
 *                 description: Origin information
 *               emergencyNumber:
 *                 type: string
 *                 description: Emergency contact number
 *               appointment_reason:
 *                 type: string
 *                 description: Reason for the appointment
 *               register_date:
 *                 type: string
 *                 format: date
 *                 description: Registration date
 *               groupmembers:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     name:
 *                       type: string
 *                       description: Name of the group member
 *                     relation:
 *                       type: string
 *                       description: Relationship with the user
 *                     age:
 *                       type: integer
 *                       description: Age of the group member
 *               externalUser:
 *                 type: boolean
 *                 description: Indicates if the member is external
 *     responses:
 *       200:
 *         description: Successful appointment creation
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: Success message
 *       404:
 *         description: User not found
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               description: User not found error message
 *       500:
 *         description: Internal Server Error
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               description: Internal Server Error message
 */


router.post("/appointment", async (req, res) => {
  try {
    const UId = req.session.UId;
    const {
 
      appointmentDate,
      num_of_people,
      pickup,
      room,  
      from,
      emergencyNumber,
      appointment_reason,
      register_date,
      groupmembers,
      externalUser
    } = req.body;
 
    const existingUser = await Users.findOne({ where: { UId } });
 
    if (!existingUser) {
      return res.status(404).json({ error: 'User not found' });
    }
 
    const newAppointment = await Appointment.create({
      UId: existingUser.UId,
      phone: existingUser.phone,
      appointmentDate,
      num_of_people,
      pickup,
      room,
      from,
      emergencyNumber,
      appointment_reason,
      register_date,
      user_name: existingUser.firstName + " " + existingUser.secondName,
      appointment_status: "Not Arrived",
      externalUser
    });
 
    if (Array.isArray(groupmembers) && groupmembers.length > 0) {
      const groupMembersData = groupmembers.map(groupMember => ({
        name: groupMember.name,
        relation: groupMember.relation,
        age: groupMember.age,
        appointmentId: newAppointment.id,
      }));
 
      await GroupMembers.bulkCreate(groupMembersData); // Fixed the function call
    }
 
    return res.status(200).json({
      message: 'Appointment has been allocated successfully! We will notify guruji soon.',
    });
  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

//////////////////////////// List Appointment ///////////////////////

/**
 * @swagger
 * /User/list-appointment:
 *   get:
 *     summary: Retrieve appointments for the authenticated user
 *     description: Endpoint to fetch appointments for the authenticated user
 *     tags:
 *       - Appointments
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: List of appointments retrieved successfully
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: Success message
 *             appointments:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                     description: Appointment ID
 *                   appointmentDate:
 *                     type: string
 *                     format: date
 *                     description: The date of the appointment
 *                   num_of_people:
 *                     type: integer
 *                     description: The number of people in the group
 *                   pickup:
 *                     type: string
 *                     description: Pickup location
 *                   room:
 *                     type: string
 *                     description: Room information
 *                   from:
 *                     type: string
 *                     description: Origin information
 *                   emergencyNumber:
 *                     type: string
 *                     description: Emergency contact number
 *                   appointment_time:
 *                     type: string
 *                     description: Time of the appointment
 *                   appointment_reason:
 *                     type: string
 *                     description: Reason for the appointment
 *                   register_date:
 *                     type: string
 *                     format: date-time
 *                     description: Date of registration
 *                   groupMembers:
 *                     type: array
 *                     items:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: integer
 *                           description: Group member ID
 *                         name:
 *                           type: string
 *                           description: Name of the group member
 *                         relation:
 *                           type: string
 *                           description: Relationship with the user
 *                         age:
 *                           type: integer
 *                           description: Age of the group member
 *       401:
 *         description: User not authenticated
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               description: Error message
 *       500:
 *         description: Internal Server Error
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               description: Internal Server Error message
 */


router.get('/list-appointment', async (req, res) => {
  try {
    const  UId = req.session.UId;
 
    // Check if the user is authenticated
    if (!UId) {
      return res.status(401).json({ error: 'User not authenticated' });
    }
 
    // Find appointments for the authenticated user
    const appointments = await Appointment.findAll({ where: { UId } });
 
    // Fetch group members for each appointment
    for (const appointment of appointments) {
      const groupMembers = await GroupMembers.findAll({ where: { appointmentId: appointment.id } });
      appointment.dataValues.groupMembers = groupMembers; // Attach group members to each appointment
    }
 
    // Respond with the list of appointments
    return res.status(200).json({ message: 'Fetching appointments', appointments });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

/////////////////////////// Delete Appointment  /////////////////

/**
 * @swagger
 * /User/delete-appointment:
 *   delete:
 *     summary: Delete an appointment and its associated group members
 *     description: Endpoint to delete an appointment and its associated group members
 *     tags:
 *       - Appointments
 *     parameters:
 *       - in: query
 *         name: id
 *         type: integer
 *         required: true
 *         description: ID of the appointment to delete
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: Appointment and associated group members deleted successfully
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: Success message
 *       401:
 *         description: User not authenticated
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               description: Error message
 *       404:
 *         description: Appointment not found
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               description: Error message
 *       500:
 *         description: Internal Server Error
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               description: Internal Server Error message
 */

router.delete('/delete-appointment', async (req, res) => {
  const { id } = req.query;
  const UId = req.session.UId; // Assuming UId is stored in req.session
 
  try {
    // Check if the user is authenticated
    if (!UId) {
      return res.status(401).json({ error: 'User not authenticated' });
    }
 
    // Start a transaction
    await sequelize.transaction(async (t) => {
      // Find the appointment
      const appointmentData = await Appointment.findOne({ where: { id }, transaction: t });
 
      // Check if the appointment exists
      if (!appointmentData) {
        return res.status(404).json({ error: 'Appointment not found' });
      }
 
      // Delete associated group members
      await GroupMembers.destroy({ where: { appointmentId: id }, transaction: t });
 
      // Delete the appointment
      await appointmentData.destroy({ transaction: t });
    });
 
    // Respond with a success message
    return res.status(200).json({ message: 'Appointment and associated group members deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

 
//////////////////update Appointment/////////////////////////////

/**
 * @swagger
 * /User/updateAppointment/{id}:
 *   put:
 *     summary: Update an appointment and its associated group members
 *     description: Endpoint to update an appointment and its associated group members
 *     tags:
 *       - Appointments
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the appointment to update
 *       - in: body
 *         required: true
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 appointmentDate:
 *                   type: string
 *                   description: The updated date of the appointment
 *                 num_of_people:
 *                   type: integer
 *                   description: The updated number of people attending the appointment
 *                 pickup:
 *                   type: boolean
 *                   description: If pickup is needed
 *                 days:
 *                   type: string
 *                   description: Number of days they stay
 *                 from:
 *                   type: string
 *                   description: The pickup location
 *                 emergencyNumber:
 *                   type: string
 *                   description: The updated emergency contact number
 *                 appointment_reason:
 *                   type: string
 *                   description: The updated reason for the appointment
 *                 register_date:
 *                   type: string
 *                   description: The updated registration date
 *                 externalUser:
 *                   type: boolean
 *                   description: Indicates if the member is external
 *                 groupmembers:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         description: ID of the group member
 *                       name:
 *                         type: string
 *                         description: Name of the group member
 *                       relation:
 *                         type: string
 *                         description: Relationship with the user
 *                       age:
 *                         type: integer
 *                         description: Age of the group member
 *     responses:
 *       200:
 *         description: Appointment and group members updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *       404:
 *         description: Appointment not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *       500:
 *         description: Internal Server Error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Internal Server Error message
 */


router.put('/updateAppointment/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateFields = req.body;
 console.log(updateFields);
    // Check if appointment exists
    const appointment = await Appointment.findOne({ where: { id } });
    if (!appointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }
 
    // Update Appointment
    const [appointmentResult] = await Appointment.update(updateFields, {
      where: { id },
    });
   // console.log(".......................",[appointmentResult]);
 
    // Update or create GroupMembers
    if (updateFields.groupmembers && Array.isArray(updateFields.groupmembers)) {
 
      const groupMembersUpdates = updateFields.groupmembers.map(async (groupMember) => {
        //console.log(groupMember.id);
        if (groupMember.id) {
         //console.log("enter");
          // Update existing group member if ID exists
          await GroupMembers.update(groupMember, {
            where: { id: groupMember.id },
          });
        } else {
         // console.log("................else........")
          // Create new group member if ID does not exist
          await GroupMembers.create({
            name: groupMember.name,
            relation: groupMember.relation,
            age: groupMember.age,
            appointmentId: id,
          });
        }
      });
      await Promise.all(groupMembersUpdates);
    }
 
    return res.status(200).json({ message: 'Appointment and GroupMembers updated successfully' });
  } catch (error) {
    //console.error('Error updating appointment and group members:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/////////////////////////// delete group member//////////////////

/**
 * @swagger
 * /User/group-members/{id}:
 *   delete:
 *     summary: Delete a group member by ID
 *     description: Delete a group member by its unique identifier.
 *     tags:
 *       - Appointments
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the group member to delete
 *     responses:
 *       '200':
 *         description: Group member deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message indicating the deletion
 *       '404':
 *         description: Group member not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message indicating the group member was not found
 *       '500':
 *         description: Internal Server Error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Internal server error message
 */

router.delete('/group-members/:id', async (req, res) => {
  const { id } = req.params;

  try {
    // Find the group member by ID
    const groupMember = await GroupMembers.findByPk(id);

    // Check if the group member exists
    if (!groupMember) {
      return res.status(404).json({ error: 'Group member not found' });
    }

    // Delete the group member
    await groupMember.destroy();

    // Respond with a success message
    return res.status(200).json({ message: 'Group member deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


router.get('/getUserById/:UId', async (req, res) => {
    try {
      const { UId } = req.params;
  
      // Fetch user details by UId from the reg table
      const user = await reg.findOne({ where: { UId } });
  
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      let profilePicUrl = null;
      if (user.profilePicUrl) {
        // If profilePicUrl exists, fetch the image URL from Firebase Storage
        const file = storage.file(user.profilePicUrl.split(storage.name + '/')[1]);
        const [exists] = await file.exists();
        if (exists) {
          profilePicUrl = await file.getSignedUrl({
            action: 'read',
            expires: '03-01-2500' // Adjust expiration date as needed
          });
        }
      }
  
      // Send the response with user data including profilePicUrl
      return res.status(200).json({
        user: {
          ...user.toJSON(),
          profilePicUrl
        }
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  router.put('/updateUser', upload.single('profilePic'), async (req, res) => {
    const UId = req.session.UId;
    const userData = req.body;
    const profilePicFile = req.file;
  
    try {
      // Check if the user is authenticated
      if (!UId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
  
      // Find the user by UId
      const user = await reg.findOne({ where: { UId } });
  
      // Update user details
      if (user) {
        // Update all fields provided in the request, excluding the profilePic field
        delete userData.profilePic; // Remove profilePic from userData
        await user.update(userData);
  
        // Fetch current profile picture URL
        let currentProfilePicUrl = user.profilePicUrl;
  
        // Store or update profile picture in Firebase Storage
        let profilePicUrl = currentProfilePicUrl; // Default to current URL
        if (profilePicFile) {
          const profilePicPath = `profile_pictures/${UId}/${profilePicFile.originalname}`;
  
          // Upload new profile picture to Firebase Storage
          await storage.upload(profilePicFile.path, {
            destination: profilePicPath,
            metadata: {
              contentType: profilePicFile.mimetype
            }
          });
  
          // Get the URL of the uploaded profile picture
          profilePicUrl = `gs://${storage.name}/${profilePicPath}`;
  
          // Delete the current profile picture from Firebase Storage
          if (currentProfilePicUrl) {
            const currentProfilePicPath = currentProfilePicUrl.split(storage.name + '/')[1];
            await storage.file(currentProfilePicPath).delete();
          }
        }
  
        // Update user's profilePicUrl in reg table
        await user.update({ profilePicUrl });
  
        return res.status(200).json({ message: 'User details updated successfully' });
      } else {
        return res.status(404).json({ error: 'User not found' });
      }
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  });
router.get('/reference', async (req, res) => {
  const UId = req.session.UId;

  try {
      const user = await reg.findOne({
          where: { UId },
          attributes: ['first_name', 'last_name'],
      });

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      const fullName = `${user.first_name} ${user.last_name}`.trim();
      res.json({ full_name: fullName });
  } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ message: 'Internal Server Error' });
  }
});
router.post('/meditation', async (req, res) => {
    try {
      const { userId } = req.session;
        const {startdatetime, stopdatetime } = req.body;

        console.log('Received userId:', userId);
        console.log('Received startdatetime:', startdatetime);
        console.log('Received stopdatetime:', stopdatetime);

        // Check if userId exists in the reg table
        const userExists = await Users.findOne({ where: { UId : userId } });
        if (!userExists) {
            return res.status(404).json({ error: 'User not found in reg table' });
        }

        const refStartDate = moment(`${startdatetime}`, "YYYY-MM-DD HH:mm:ss", true);
        const refFutureDate = refStartDate.clone().add(45, "minutes");
        const refStopDate = moment(`${stopdatetime}`, "YYYY-MM-DD HH:mm:ss", true);

        console.log('Parsed startdatetime:', refStartDate.format('YYYY-MM-DD HH:mm:ss'));
        console.log('Parsed stopdatetime:', refStopDate.format('YYYY-MM-DD HH:mm:ss'));

        const difference = refStopDate.diff(refStartDate, 'minutes');
        if(difference>=90){
          ismeditated = 1
        }
        else{
          ismeditated = 2
        }

        console.log('Difference:', difference);
        const TimeTracking = await timeTracking.create({
            userId,
            med_starttime: refStartDate.format('YYYY-MM-DD HH:mm:ss'),
            med_stoptime:refStopDate.format('YYYY-MM-DD HH:mm:ss'),
            timeEstimate:difference,
            ismeditated
        });
        await TimeTracking.save();

        // Check if there is an existing record for the userId
        const existingMeditationRecord = await Meditation.findOne({ where: { userId } });

        if (existingMeditationRecord) {
            // Update the existing record
            existingMeditationRecord.med_starttime = refStartDate.format('YYYY-MM-DD HH:mm:ss');
            existingMeditationRecord.med_stoptime = refStopDate.format('YYYY-MM-DD HH:mm:ss');
            existingMeditationRecord.med_endtime = refFutureDate.format('YYYY-MM-DD HH:mm:ss');

            if (difference >= 45) {
                existingMeditationRecord.session_num += 1 ;
                if(existingMeditationRecord.session_num > 2) {
                    existingMeditationRecord.session_num = 1; 
            }}

            if (existingMeditationRecord.session_num === 2) {
                existingMeditationRecord.day += 1;
                //existingMeditationRecord.session_num = 0;
            }

            if (existingMeditationRecord.day === 15) {
                existingMeditationRecord.cycle += 1;
                existingMeditationRecord.day = 0;
            }

            await existingMeditationRecord.save();
            return res.status(200).json({ message: 'Meditation time updated successfully' });
        } else {
            // Create a new record if there is no existing record
            const meditationRecord = await Meditation.create({
                userId,
                med_starttime: refStartDate.format('YYYY-MM-DD HH:mm:ss'),
                med_stoptime: refStopDate.format('YYYY-MM-DD HH:mm:ss'),
                med_endtime: refFutureDate.format('YYYY-MM-DD HH:mm:ss'),
                session_num: 0,
                day: 0,
                cycle: 0,
            });

            if (difference >= 45) {
                meditationRecord.session_num += 1;
            }

            if (meditationRecord.session_num === 2) {
                meditationRecord.day += 1;
                meditationRecord.session_num = 0;
            }

            if (meditationRecord.day === 41) {
                meditationRecord.cycle += 1;
                meditationRecord.day = 0;
            }

            await meditationRecord.save();
            return res.status(200).json({ message: 'Meditation time inserted successfully' });

        }

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});
 
router.get('/reg-confiq', async (req, res) => {
  try{
  const config = await applicationconfig.findAll();
  res.json({ config });
  }
  catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

 router.post('/meditation', async (req, res) => {
  try {
   // const { UId } = req.body;
      const { UId } = req.session;
      const { startdatetime, stopdatetime } = req.body;

      console.log('Received UId:', UId);
      console.log('Received startdatetime:', startdatetime);
      console.log('Received stopdatetime:', stopdatetime);

      // Check if UId exists in the reg table
      const userExists = await Users.findOne({ where: { UId } });
      if (!userExists) {
          return res.status(404).json({ error: 'User not found in reg table' });
      }

      const refStartDate = moment(`${startdatetime}`, "YYYY-MM-DD HH:mm:ss", true);
      const refFutureDate = refStartDate.clone().add(45, "minutes");
      const refStopDate = moment(`${stopdatetime}`, "YYYY-MM-DD HH:mm:ss", true);

      console.log('Parsed startdatetime:', refStartDate.format('YYYY-MM-DD HH:mm:ss'));
      console.log('Parsed stopdatetime:', refStopDate.format('YYYY-MM-DD HH:mm:ss'));

      const difference = refStopDate.diff(refStartDate, 'minutes');
      let ismeditated;

      if (difference >= 90) {
          ismeditated = 1;
      } else {
          ismeditated = 2;
      }

      console.log('Difference:', difference);
      const TimeTracking = await timeTracking.create({
          UId,
          med_starttime: refStartDate.format('YYYY-MM-DD HH:mm:ss'),
          med_stoptime: refStopDate.format('YYYY-MM-DD HH:mm:ss'),
          timeEstimate: difference,
          ismeditated
      });
      await TimeTracking.save();

      // Check if there is an existing record for the UId
      const existingMeditationRecord = await Meditation.findOne({ where: { UId } });

      if (existingMeditationRecord) {
          // Update the existing record
          existingMeditationRecord.med_starttime = refStartDate.format('YYYY-MM-DD HH:mm:ss');
          existingMeditationRecord.med_stoptime = refStopDate.format('YYYY-MM-DD HH:mm:ss');
          existingMeditationRecord.med_endtime = refFutureDate.format('YYYY-MM-DD HH:mm:ss');

          if (difference >= 45) {
              existingMeditationRecord.session_num += 1;
              if (existingMeditationRecord.session_num > 2) {
                  existingMeditationRecord.session_num = 1;
              }
          }

          if (existingMeditationRecord.session_num === 2) {
              existingMeditationRecord.day += 1;
              //existingMeditationRecord.session_num = 0;
          }

          if (existingMeditationRecord.day === 41) {
              existingMeditationRecord.cycle += 1;
              existingMeditationRecord.day = 0;
          }

          await existingMeditationRecord.save();
          return res.status(200).json({ message: 'Meditation time updated successfully' });
      } else {
          // Create a new record if there is no existing record
          const meditationRecord = await Meditation.create({
              UId,
              med_starttime: refStartDate.format('YYYY-MM-DD HH:mm:ss'),
              med_stoptime: refStopDate.format('YYYY-MM-DD HH:mm:ss'),
              med_endtime: refFutureDate.format('YYYY-MM-DD HH:mm:ss'),
              session_num: 0,
              day: 0,
              cycle: 0,
          });

          if (difference >= 45) {
              meditationRecord.session_num += 1;
          }

          if (meditationRecord.session_num === 2) {
              meditationRecord.day += 1;
              meditationRecord.session_num = 0;
          }

          if (meditationRecord.day === 41) {
              meditationRecord.cycle += 1;
              meditationRecord.day = 0;
          }

          await meditationRecord.save();
          return res.status(200).json({ message: 'Meditation time inserted successfully' });

      }

  } catch (error) {
      console.error('Error:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
  }
});

//   router.post('/send-email', async (req, res) => {
//   try {
//     const {first_name,last_name,UId,DOJ,expiredDate} = req.body
//     const to = req.body.to
//     const config = await applicationconfig.findOne(); // Retrieve a single row from the table
//     const prompt = config ? config.reg_email_prompt : null;
//     // const reg_email_prompt = applicationconfig.reg_email_prompt;
//     console.log(prompt)
//     // Create a Nodemailer transporter
//     const transporter = nodemailer.createTransport({
//       host: 'smtp.forwardemail.net',
//       port: 465,
//       secure: true,
//       service: 'gmail',
//       auth: {
 
//         user: 'thasmaistarlife@gmail.com',
//         pass: 'ndkj dxdq kxca zplg',
//       },
//     });
 
//     // Define email options
//     const mailOptions = {
//       from: 'thasmaistarlife@gmail.com',
//       to,
//       subject: 'Thasmai Star Life : Registration Success Email',
//       text: 'Your registration is complete!',
//       html: `
 
//       <head>
//       <meta name="viewport" content="width=device-width, initial-scale=1.0">
//       <link rel="preconnect" href="https://fonts.googleapis.com">
//       <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
//       <link href="https://fonts.googleapis.com/css2?family=Kalnia:wght@100;200;300;400;500;600;700&family=Poppins:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet">
//       <style>
//           .headers {
//               text-align: center;
//               height: auto;
//               padding: 20px 0;
//           }
//           .message {
//               text-align: justify;
//               width: 90%;
//               max-width: 400px;
//               margin: 0 auto;
//               padding: 10px;
//               box-sizing: border-box;
//           }
//           .message p {
//               margin: 5px 0;
//           }
 
//           .whatsapp-icon {
//               height: 40px;
//               width: 40px;
//               border-radius: 100%;
//          }
 
//           .whatsapp-link {
//               margin-top: 20px;
//               color: rgb(37, 61, 183);
//               font-weight: 600;
//               font-size: 1rem;
//           } 
 
//       .card-container{
 
//         text-align: center;
 
//       }
 
 
//       .reg-success-card {
//         background-image: url('https://lh3.googleusercontent.com/u/0/drive-viewer/AEYmBYTWA0bZqZRaGcd2yXoQu_AzBPv36ZDRHbeYm7rcVap0nQ1Dk16LUmtFnuWfmfdMGGkrVmZpw2Hg37ay2o6qgG-WAV6D=w1920-h922');
//         background-repeat: no-repeat;
//         background-color: rgb(62, 61, 91);
//         background-size: cover;
//         border-radius: 19px;
//         height: 240px;
//         width: 400px;
//         text-align: center;
//         margin:50px auto;
//       }
 
//       .reg-success-card-head {
//         margin: 0;
//         padding: 3% 0 0;
//         height: 30%;
//         width: 100%;
//       }
 
//       .reg-card-number {
//         text-align: left;
//         color: white;
//         padding-left: 25px;
//       }
 
//       .reg-card-number p {
//         font-size: 0.6rem;
//         margin: 0;
//         text-wrap: nowrap;
//       }
 
//       .reg-card-number h1 {
//         font-size: 1.1rem;
//         font-weight: bold;
//         margin: 0;
//       }
 
//       .reg-card-logo {
//         width: 12%;
//         padding-right: 25px;
//       }
 
//       .logo-container{
//         text-align: right;
//       }
 
//       .reg-success-card-content {
//         height: 30%;
//       }
 
//       .content-chip{
//         width: 20%;
//       }
 
//       .chip {
//         width: 40%;
//       }
 
//       .center-content{
//         text-align: left;
//         width: 60%;
//       }
 
//       .reg-success-card-content div {
//         margin: 0;
//         padding: 0;
//         text-align: center;
//       }
 
//       .reg-card-star-life-logo {
//         width: 35%;
//         margin: 0;
//         padding: 0;
//       }
 
//       .reg-card-contact-number {
//         font-size: 0.8rem;
//         font-weight: bold;
//         margin: 0;
//         color: #fff;
//       }
 
//       .reg-card-success-message {
//         color: #f4e893;
//         font-size: 1.1rem;
//         margin: 3px 0;
//       }
 
//       .empty-cell{
//         width: 20%;
//       }
 
//       .reg-success-card-footer {
//         margin: 0;
//         padding: 0 0 3%;
//         width: 100%;
//         height: 40%;
//       }
 
//       .card-holder-group {
//         text-align: left;
//         color: white;
//         padding-left: 25px;
//       }
 
//       .card-holder-name p {
//         font-size: 0.6rem;
//         margin: 0;
//       }
 
//       .card-holder-name h2 {
//         font-size: 1.1rem;
//         font-weight: bold;
//         margin: 0;
//       }
 
//       .reg-card-validity{
//        padding-right: 25px;
//        text-align: right;
//       }
 
//       .reg-card-validity p {
//         font-size: 0.6rem;
//         margin: auto;
//         color: #ffffff;
//       }
 
 
 
 
//       </style>
//   </head>
 
//   <body>
//   <div class="headers">
//       <h1 style="margin: 0;">Welcome to Thasmai</h1>
//       <p style="margin: 5px 0;">Sathyam Vada || Dharmam Chara</p>
//   </div>
//   <div class="message" style="color: #4F4539;">
//       <p>Hi ${first_name} ${last_name},</p>
//       <p>Congratulations! Registration complete. Your register number: ${UId}.</p>
//       <p>To receive further details about the introduction class (zoom session): Please send a “hi” to number ‘+91 9900829007’. Thank you for taking the first step.</p>
 
//       <p class="whatsapp-link"></p>
//       <img class="whatsapp-icon" src="https://lh3.googleusercontent.com/u/0/drive-viewer/AEYmBYSnIUgsI2fYvK6_gntrPiT71yOQNKVBOjFaRj6IBkTqFB6XeOj2ucTd_zVvb8P_mCNQTc44g-MWkvmQctQ0q9-7WXEzyw=w1920-h922" alt="">
 
//           <a class="whatsapp-link" href="https://wa.me/+919008290027">Click here to Join Whatsapp Group</a>
//       </p>
//   </div>
 
//  <!-- ertyu--------------------------------------------------------------------------- -->
//  <div class="card-container">
 
 
 
//   <div class="reg-success-card">
//     <table  class="reg-success-card-head">
//       <tr>
//       <td class="reg-card-number">
//         <p>Card Number</p>
//         <!-- <h1>{data.userId}</h1> -->
//         <h1>${UId}</h1>
//       </td>
//          <td class="logo-container">
//       <img class="reg-card-logo" src="https://lh3.googleusercontent.com/u/0/drive-viewer/AEYmBYSV8OQTMueB3tVPRLnS4G7ogutUDfJ8bxG0aSVEgoCF4ULoC0kMv1jqRjuwX-39JSXFw34gAhoiARJ444BG7wiyiaW4=w1227-h922" alt="Thasmai logo" />
//     </td> 
//     </tr>
//     </table>
 
//     <table class="reg-success-card-content">
//       <tr>
//         <td class="content-chip">
//       <img class="chip" src="https://lh3.googleusercontent.com/u/0/drive-viewer/AEYmBYSDv_6wQFPu6a321tH8lrNiPqVRhyOKOiWiTwK4dFhf7LqPyqu3JHwoUjeeZK4Lf2PwKqhcMHATBrJ7i_uVzbNcNpbZHQ=w1920-h922" alt="chip" />
//     </td>
//     <td class="center-content">
//       <div>
//         <img class="reg-card-star-life-logo" src="https://lh3.googleusercontent.com/u/0/drive-viewer/AEYmBYQNvO2hAP--VETE3_IPAsKI5McAw4EhsbXPVCbTbvfbN9k_jLs4lHTJWhWJwweNuRdxERjL5p8PfXPfO4X28PS_IYVF_g=w1920-h922" alt="star-life-img" />
//         <h3 class="reg-card-success-message">Registration Successful</h3>
//         <p class="reg-card-contact-number">
//           <span>Contact: +91 9008290027</span>
//         </p>
//         <!-- <a class="success-page-link" href="/registrationSuccess">OK</a> -->
//       </div>
//     </td>
//     <td class="empty-cell"></td>
//     </tr>
 
//     </table>
 
//     <table class="reg-success-card-footer">
//       <tr>
//       <td class="card-holder-group">
//         <div class="card-holder-name">
//           <p>Cardholder Name</p>
//           <!-- <h2>{data.first_name} {data.last_name}</h2> -->
//           <h2>${first_name} ${last_name}</h2>
//           <!-- <p>DOJ: {dayOfJoining + "/" + monthOfJoining + "/" + yearOfJoining}</p> -->
//           <p>DOJ:${DOJ}</p>
//         </div>
//       </td>
 
//       <td class="reg-card-validity">
//         <!-- <p>VALID: {expiry.day}/{expiry.month}/{expiry.year}</p> -->
//         <p>VALID:${expiredDate}</p>
//       </td>
//     </tr>
//     </table>
//   </div>
//    <!--end of card container--> 
 
 
//    <div>
//   <p>Click the link below to download our app</p>
//   <a href="https://drive.google.com/file/d/1QkYpKY_v6epzn9SmkP7stkhKFp4to_DZ/view" target = "_blank" style = "width:100px; height:20px; padding :10px; background-color:  #219cc9; text-decoration: none; color:white;">Download</a>
//  </div>
// </body>`,
//     };
 
//     // Send the email
//     transporter.sendMail(mailOptions, (error, info) => {
//       if (error) {
//         console.error('Error:', error);
//       } else {
//         console.log('Email sent:', info.response);
//       }
//     return res.status(200).json({ message: 'Email sent successfully' });
//     });
//   } catch (error) {
//     console.error('Error:', error);
//     r routereturn res.status(500).json({ error: 'Internal Server Error' });
//   }
// });

// router.get('/meditation-detail', async (req, res) => {
//   try {
//        const { UId } = req.session;
//       //const UId = req.body.UId;
//       if (!UId) {
//           return res.status(401).json({ error: 'User not authenticated' });
//       }

//       const user = await meditation.findOne({
//           attributes: ['UId', 'med_starttime', 'med_stoptime', 'med_endtime', 'session_num', 'day', 'cycle'],
//           where: { UId: UId },
//       });

//       if (!user) {
//           return res.status(404).json({ error: 'User not found' });
//       }

//       return res.status(200).json(user);
//   } catch (error) {
//       console.error('Error:', error);
//       return res.status(500).json({ error: 'Internal Server Error' });
//   }
// });


  router.get('/get-messages', async (req, res) => {
  try {
      const  { UId } = req.session;
      //console.log('UId', UId);
     // const { UId } = req.body;

      if (!UId) {
          return res.status(401).json({ error: 'User not authenticated' });
      }

      const messages = await Messages.findAll({
          attributes: ['UId', 'message', 'messageTime','isAdminMessage','messagetype'],
          where: { UId: UId },
      });

      if (!messages || messages.length === 0) {
          return res.status(404).json({ error: 'Messages not found for the user' });
      }

      return res.status(200).json(messages);
  } catch (error) {
      console.error('Error:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
  }
});



// router.get('/meditation-date', async (req, res) => {
//   try {
//       const { UId } = req.session;

//      // const { UId } = req.body;


//       if (!UId) {
//           return res.status(401).json({ error: 'User not authenticated' });
//       }

//       const user = await timeTracking.findAll({
//           attributes: ['UId', 'med_starttime', 'timeEstimate', 'ismeditated'],
//           where: {
//             UId: UId,
//           },
//       });

//       if (!user || user.length === 0) {
//           return res.status(404).json({ error: 'No records found with timeEstimate >= 90' });
//       }

//       // Modify the med_starttime in each record
//       const formattedUser = user.map(record => {
//           const parsedDate = moment(record.med_starttime, "YYYY-MM-DD HH:mm:ss");
//           const formattedDate = parsedDate.format("YYYY-MM-DD HH:mm:ss");
//           const replacedDate = formattedDate.replace(/-/g, ',');

//           // Add the formatted date to the record
//           return { ...record.dataValues, med_starttime: replacedDate };
//       });

//       return res.status(200).json(formattedUser);
//   } catch (error) {
//       console.error('Error:', error);
//       return res.status(500).json({ error: 'Internal Server Error' });
//   }
// });

// router.get('/getBankDetails/:userId', async (req, res) => {
//   try {
//     const userId = parseInt(req.params.UId);

//     // Fetch the 'reg' record with associated 'BankDetails'
//     const userData = await reg.findOne({
//       where: { userId },
//       include: [BankDetails], // Include the associated BankDetails
//     });

//     if (!userData) {
//       return res.status(404).json({ message: 'User not found' });
//     }

//     // Access the BankDetails from the retrieved data
//     const userBankDetails = userData.BankDetail; // assuming you've defined it as "BankDetail" in the reg model

//     res.json({ userData, userBankDetails });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// router.get('/getbroadcast-message', async (req, res) => {
//   try {
//     const messages = await Broadcast.findAll();
//     res.json({ messages });
//   } catch (error) {
//     console.error('Error:', error);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });

// router.get('/show', async (req, res) => {
// try {
    
//     const config = await applicationconfig.findOne(); // Retrieve a single row from the table
//     const prompt = config ? config.reg_email_prompt : null; // Access the reg_email_prompt property
//     console.log(prompt);
//     res.status(200).json({ prompt });
// } catch (error) {
//     console.error('Error:', error);
//     res.status(500).json({ error: 'Internal Server Error' });
// }
// });

// router.put('/update-msg/:id', async (req, res) => {
//   const { UId } = req.session;
//   const id = req.params.id;
//   const { togurugi } = req.body;

//   try {
//     // Check if the user exists and has the right to update the message
//     const existingUser = await Users.findOne({ where: { UId } });
//     if (!existingUser) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     const operatorMsgToUpdate = await operatorMsg.findOne({ where: { id } });
//     if (!operatorMsgToUpdate) {
//       return res.status(404).json({ error: 'Operator message not found' });
//     }

//     // Update the operatorMsg
//     await operatorMsgToUpdate.update({ togurugi });

//     if (togurugi === 'on') {
//       // Pass the updated data to the Messages model
//       const newMessage = await Messages.create({
//         UId,
//         message: operatorMsgToUpdate.message,
//         messageTime: operatorMsgToUpdate.messageTime,
//         message_priority: operatorMsgToUpdate.message_priority,
//         isAdminMessage: operatorMsgToUpdate.isAdminMessage,
//         messagetype: operatorMsgToUpdate.messagetype,
//       });

//       // Remove the message from the operatorMsg model
//       await operatorMsgToUpdate.destroy();

//       return res.status(200).json({ message: 'Message moved and updated successfully' });
//     } else {
//       return res.status(200).json({ message: 'Message updated successfully' });
//     }

//   } catch (error) {
//     console.error('Error:', error);
//     return res.status(500).json({ error: 'Internal Server Error' });
//   }
// });

// router.get('/private-msg' , async(req,res) =>{
//   const UId= req.session.UId;
//   try{
//     if(!UId){
//       res.status(401).json('user not authenticated');
//     }
//    // console.log("..........",UId);
//     const messages = await privateMsg.findAll({
//       attributes: ['message', 'messageTime', 'message_priority'],
//       where: { UId: UId },
//       order: [['messageTime', 'ASC']]
//     });
//     //console.log("message",messages);
//     if (!messages || messages.length === 0) {
//       return res.status(404).json({ error: 'Messages not found for the user' });
//   }

//   return res.status(200).json(messages);
// } catch (error) {
//   console.error('Error:', error);
//   return res.status(500).json({ error: 'Internal Server Error' });
// }
// });

// router.get('/gurugi-msg' , async(req,res) =>{
//   const UId= req.session.UId;
//   try{
//     if(!UId){
//       res.status(401).json('user not authenticated');
//     }
//     //console.log("..........",UId);
//     const messages = await message.findAll({
//       attributes: ['message', 'messageTime', 'message_priority'],
//       where: { UId: UId },
//       order: [['messageTime', 'ASC']]
//     });
//    // console.log("message",messages);
//     if (!messages || messages.length === 0) {
//       return res.status(404).json({ error: 'Messages not found for the user' });
//   }

//   return res.status(200).json(messages);
// } catch (error) {
//   console.error('Error:', error);
//   return res.status(500).json({ error: 'Internal Server Error' });
// }
// });

// router.get('/global-msg' , async(req,res) =>{
//   const UId= req.session.UId;
//   try{
//     if(!UId){
//       res.status(401).json('user not authenticated');
//     }
//     //console.log("..........",UId);
//     const messages = await operatorMsg.findAll({
//       attributes: ['message', 'messageTime', 'message_priority'],
//       where: { UId: UId } && { messagetype : 'global'},
//       order: [['messageTime', 'ASC']]
//     });
//    // console.log("message",messages);
//     if (!messages || messages.length === 0) {
//       return res.status(404).json({ error: 'Messages not found for the user' });
//   }

//   return res.status(200).json(messages);
// } catch (error) {
//   console.error('Error:', error);
//   return res.status(500).json({ error: 'Internal Server Error' });
// }
// });

module.exports = router;