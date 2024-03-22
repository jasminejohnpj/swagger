const express = require('express');
const { sequelize, reg } = require('../model/registration');
const router = express.Router();
const {Users} = require('../model/validUsers');
const { Op } = require("sequelize");
const Distribution = require('../model/distribution');
const financialconfig = require('../model/financialConfig');
const BankDetails = require('../model/bankdetails');
const mahadhanam =require('../model/mahadhanam');
const events = require('../model/events')
const coupondistribution = require('../model/coupondistribution');
const message =require('../model/message')
//const multer= require('multer');
const meditation =require('../model/meditation');
const Notification = require('../model/notification');
const { validationResult } = require('express-validator');
const Broadcast =require('../model/broadcast');
const admin =require('firebase-admin');
const serviceAccount = require("../serviceAccountKey.json");
const Appointment = require("../model/appointment");
const supportcontact =require('../model/supportContactConfig');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const GroupMembers = require('../model/groupmembers');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: "gs://thasmai-star-life.appspot.com"
});
const storage = admin.storage().bucket();

router.get('/register-count', async (req, res) => {
  try {
      const { month, year } = req.query;

      // Validate client input
      if (!month && !year) {
          return res.status(400).json({ message: 'Please provide month or year parameter' });
      }

      let groupBy;
      let attributes;
      let additionalConditions = {};

      if (month) {
          // If month is provided, get the count for each day in that month
          groupBy = [sequelize.fn('DAY', sequelize.col('DOJ'))];
          attributes = [
              [sequelize.fn('DAY', sequelize.col('DOJ')), 'day'],
              [sequelize.fn('COUNT', '*'), 'count'],
          ];
          additionalConditions = {
            DOJ: {
                [Op.between]: [`${year}-${month}-01`, `${year}-${month}-31`],
            },
        };
      } else if (year) {
          // If year is provided, get the count for each month in that specific year
          groupBy = [sequelize.fn('MONTH', sequelize.col('DOJ'))];
          attributes = [
              [sequelize.fn('MONTH', sequelize.col('DOJ')), 'month'],
              [sequelize.fn('COUNT', '*'), 'count'],
          ];

          // Filter results for the specified year
          additionalConditions = {
              DOJ: {
                  [Op.between]: [`${year}-01-01`, `${year}-12-31`],
              },
          };
      }

      const registerCounts = await reg.findAll({
          attributes: attributes,
          where: {
              ...additionalConditions, // Include additional conditions if provided
          },
          group: groupBy,
          order: groupBy, // Ensure order by the specified time unit
      });

      res.json(registerCounts);
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
  }
});
router.get('/waiting-list', async (req, res) => {
  try {
    const list = await reg.count({
      where: {
        classAttended: 'false'
      }
    });

    res.json({list});
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
router.get('/meditation', async (req, res) => {
  try {
    const list = await meditation.count({});

    res.json({list});
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
router.get('/beneficiaries', async (req, res) => {
  try {
      
      const firstTenUserIds = (await Users.findAll({
          attributes: ['UserId'],
          order: [['UserId', 'ASC']],
          limit: 10,
      })).map(user => user.UserId);

      
      const count = await Users.count({
          where: {
              UserId: {
                  [Op.notIn]: firstTenUserIds,
              },
              coupons: {
                  [Op.ne]: 0,
              },
          },
      });

      return res.json({ count });
  } catch (err) {
      console.log(err);
      return res.status(500).json({ error: 'Internal Server Error' });
  }
});
router.post('/add-event', upload.single('image'), async (req, res) => {
  const { event_name, event_description, priority, place, date ,event_time } = req.body;
  const eventImageFile = req.file;
  
  try {
    
    if (!event_name || !event_description || !priority || !place || !date) {
      return res.status(400).send({ error: 'Missing required fields' });
    }

    const newEvent = await events.create({
      event_name,
      event_description,
      priority,
      place,
      date,
      event_time
    });

    
    let image = ''; 
    if (eventImageFile) {
      const eventImagePath = `event_image/${newEvent.id}/${eventImageFile.originalname}`;

      
      await storage.upload(eventImageFile.path, {
        destination: eventImagePath,
        metadata: {
          contentType: eventImageFile.mimetype
        }
      });

      image = `gs://${storage.name}/${eventImagePath}`;
    }

    await newEvent.update({ image });

    res.status(201).json({ message: 'Event created successfully', event: newEvent });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.get('/events', async (req, res) => {
  try {
    
    const allEvents = await events.findAll();

    
    const everyEvents = allEvents.map(event => {
      return {
        id: event.id,
        event_name: event.event_name,
        event_description: event.event_description,
        priority: event.priority,
        place: event.place,
        date: event.date,
        event_time : event.event_time
       // image: event.image.toString('base64'), 
      };
    });

    res.status(200).json({ events: everyEvents });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.put('/update-event/:id', upload.single('image'), async (req, res) => {
  const id = req.params.id;
  const userData = req.body;
  const eventImageFile = req.file;

  try {
    // Check if the user is authenticated
    if (!id) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Find the user by UId
    const user = await events.findOne({ where: { id } });

    // Update user details
    if (user) {
      // Update all fields provided in the request, excluding the profilePic field
      delete userData.image; // Remove profilePic from userData
      await user.update(userData);

      // Fetch current profile picture URL
      let currentProfilePicUrl = user.image;

      // Store or update profile picture in Firebase Storage
      let image = currentProfilePicUrl; // Default to current URL
      if (eventImageFile) {
        const profilePicPath = `event_image/${id}/${eventImageFile.originalname}`;
        // Upload new profile picture to Firebase Storage
        await storage.upload(eventImageFile.path, {
          destination: profilePicPath,
          metadata: {
            contentType: eventImageFile.mimetype
          }
        });

        // Get the URL of the uploaded profile picture
        image = `gs://${storage.name}/${profilePicPath}`;

        // Delete the current profile picture from Firebase Storage
        if (currentProfilePicUrl) {
          const currentProfilePicPath = currentProfilePicUrl.split(storage.name + '/')[1];
          await storage.file(currentProfilePicPath).delete();
        }
      }

      // Update user's profilePicUrl in reg table
      await user.update({ image });

      return res.status(200).json({ message: 'event details updated successfully' });
    } else {
      return res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    //console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.get('/get-event/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Fetch user details by UId from the reg table
    const user = await events.findOne({ where: { id } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    let image = null;
    if (user.image) {
      // If profilePicUrl exists, fetch the image URL from Firebase Storage
      const file = storage.file(user.image.split(storage.name + '/')[1]);
      const [exists] = await file.exists();
      if (exists) {
        image = await file.getSignedUrl({
          action: 'read',
          expires: '03-01-2500' // Adjust expiration date as needed
        });
      }
    }

    // Send the response with user data including profilePicUrl
    return res.status(200).json({
      user: {
        ...user.toJSON(),
        image
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
router.delete('/delete-events/:eventId', async (req, res) => {
  try {
      const eventId = req.params.eventId;
      const event = await events.findByPk(eventId);

      if (!event) {
          return res.status(404).json({ error: 'Event not found' });
      }
      await event.destroy();

      res.status(200).json({ message: 'Event deleted successfully' });
  } catch (error) {
      console.log(error);
      res.status(500).json({ error: 'Internal Server Error' });
  }
});
router.get('/messages', async (req, res) => {
  try {
      const priority = req.query.priority; 

      if (!priority) {
          return res.status(400).json({ message: 'Priority parameter is required' });
      }

      const messages = await message.findAll({
          where: {
              message_priority: priority.toLowerCase() 
          }
      });

      return res.status(200).json(messages);
  } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Internal Server Error' });
  }
});


router.get('/searchfield', async (req, res) => {
  try {
    const field = req.query.field; // Retrieve the field from query parameters
    const value = req.query.value; // Retrieve the value from query parameters

    if (!field || !value) {
      return res.status(400).json({ message: 'Please provide both field and value parameters' });
    }
      
    const lowerCaseValue = value.toLowerCase();

    // You can now use the field and value to search the database and fetch details
    const userDetails = await Users.findAll({
      where: {
        [field]: lowerCaseValue,
      },
    });

    if (!userDetails) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Success', data: userDetails });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


router.post('/coupon-distribute', async (req, res) => {
  try {
    const { totalCoupons, distributedIds, description } = req.body;

    // Validate input
    if (!totalCoupons || !distributedIds || !Array.isArray(distributedIds)) {
      return res.status(400).json({ message: 'Invalid input. Please provide totalCoupons and an array of distributedIds.' });
    }

    // Check if totalCoupons is a positive integer
    if (!Number.isInteger(totalCoupons) || totalCoupons <= 0) {
      return res.status(400).json({ message: 'Invalid input. totalCoupons should be a positive integer.' });
    }

    // Fetch user IDs and corresponding coupon numbers in descending order
    const usersWithCoupons = await Users.findAll({
      attributes: ['UserId', 'coupons'],
      order: [['coupons', 'DESC']], // Order by UserId in descending order
      limit: totalCoupons,
      where: {
        UserId: { [Op.gt]: 11 },
        coupons: { [Op.gt]: 0 }, // Start from UserId 11
      }, // Exclude the first 10 records
    });

    console.log("........................................................", usersWithCoupons);

    // Check if enough coupons are available for distribution
    if (usersWithCoupons.length < totalCoupons) {
      return res.status(400).json({ message: 'Not enough coupons available to distribute.' });
    }

    // Build the where condition to ensure coupons is greater than or equal to 1
    const whereCondition = {
      UserId: usersWithCoupons
        .filter((user) => user.coupons > 0) // Filter out users with 0 coupons
        .map((user) => user.UserId),
      coupons: { [Op.gte]: 1 }, // Ensure coupons is greater than or equal to 1
    };
    //console.log("whereCondition........................................................................", whereCondition);

    const updatedCoupons = await Users.update(
      { coupons: sequelize.literal('coupons - 1') },
      { where: whereCondition }
    );

    const couponsPerUser = totalCoupons / distributedIds.length;

    // Update Users table with couponsPerUser for each distributed user
    await Promise.all(distributedIds.map(async (UserId) => {
      const user = await Users.findByPk(UserId);
      if (user) {
        // Update coupons in the Users table by adding couponsPerUser
        await Users.update(
          { coupons: sequelize.literal(`coupons + ${couponsPerUser}`) },
          { where: { UserId: UserId } }
        );
              }
    }));

    // Send response after all updates are complete
    res.json({ message: 'Coupons distributed successfully', updatedCoupons });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/export', async (req, res) => {
  try {
    const { coupons, UIds, description } = req.body;

    // Validate input
    if (!coupons || !UIds || !Array.isArray(UIds) || UIds.length === 0) {
      return res.status(400).json({ message: 'Invalid input. Please provide coupons and a non-empty array of UIds.' });
    }

    // Check if coupons is a positive integer
    if (!Number.isInteger(coupons) || coupons <= 0) {
      return res.status(400).json({ message: 'Invalid input. Coupons should be a positive integer.' });
    }

    // Fetch users with specified UIds and valid coupons
    const usersToUpdate = await Users.findAll({
      where: {
        UId: UIds,
        coupons: { [Op.gte]: coupons },
      },
    });

    // Check if enough coupons are available for all specified users
    if (usersToUpdate.length !== UIds.length) {
      return res.status(400).json({ message: 'Not enough coupons available for all specified users.' });
    }

    // Update coupons for each user
    const updatedUsers =await Promise.all(usersToUpdate.map(async (user) => {
      const updatedCoupons = user.coupons - coupons;
      await Users.update({ coupons: updatedCoupons }, { where: { UId: user.UId } });
      await Distribution.create({
        firstName: user.firstName,
        secondName: user.secondName,
        UId: user.UId,
        distributed_coupons: coupons,
        description: description,
        distribution_time: new Date().toISOString(),
      });

      //////////////////////////////////
      const latestDistributionRecord = await Distribution.findOne({
        attributes: ['firstName', 'secondName', 'UId', 'distributed_coupons', 'description', 'distribution_time'],
        where: { UId: user.UId },
        order: [['distribution_time', 'DESC']], // Order by distribution_time in descending order to get the latest record
      });

      // Fetch the corresponding bank details for the user
      const bankDetails = await BankDetails.findOne({
        attributes: ['AadarNo', 'IFSCCode', 'branchName', 'accountName', 'accountNo'],
        where: { UId: user.UId },
      });

      return {
        firstName: latestDistributionRecord.firstName,
        secondName: latestDistributionRecord.secondName,
        UId: latestDistributionRecord.UId,
        distributed_coupons: latestDistributionRecord.distributed_coupons,
        description: latestDistributionRecord.description,
        distribution_time: latestDistributionRecord.distribution_time,
        AadarNo: bankDetails.AadarNo,
        IFSCCode: bankDetails.IFSCCode,
        branchName: bankDetails.branchName,
        accountName: bankDetails.accountName,
        accountNo: bankDetails.accountNo,
      };
    }));

    res.json({ message: 'Coupons reduced successfully for specified users.',distributionDetails: updatedUsers});
    } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/distribute-coupons', async (req, res) => {
  try {
    const { UIds, couponsToDistribute } = req.body;

    const users = await Users.findAll({ where: { UId: UIds } });

    if (!users || users.length === 0) {
      return res.status(404).json({ error: 'Users not found' });
    }

    const insufficientCouponUsers = users.filter(user => user.coupons < couponsToDistribute);
    if (insufficientCouponUsers.length > 0) {
      return res.status(400).json({ error: 'Not enough coupons to distribute for some users' });
    }

    let totalCouponsDistributed = 0;

    await sequelize.transaction(async (t) => {
      for (const user of users) {
        user.coupons -= couponsToDistribute;
        await user.save();

        const distributionRecord = await coupondistribution.create({
          firstName: user.firstName,
          secondName: user.secondName,
          UId: user.UId,
          coupons_to_distribute: couponsToDistribute,
          distribution_time: new Date().toISOString(),
        }, { transaction: t });
        
      }
    });

    const totalCouponsInDistributionTable = await coupondistribution.sum('coupons_to_distribute');


    return res.status(200).json({ message: 'Coupons distributed successfully',totalCouponsInDistributionTable: totalCouponsInDistributionTable });
  } catch (error) {
    console.log('Error distributing coupons:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/revoke-coupons', async (req, res) => {
  try {
    const { UIds } = req.body;

    // Retrieve coupon distribution details
    const couponDistributionRecords = await coupondistribution.findAll({ where: { UId: UIds } });

    if (!couponDistributionRecords || couponDistributionRecords.length === 0) {
      return res.status(404).json({ error: 'Coupon distribution records not found' });
    }

    // Update Users table to return coupons
    await sequelize.transaction(async (t) => {
      for (const record of couponDistributionRecords) {
        const user = await Users.findOne({ where: { UId: record.UId } });

        if (user) {
          // Add the distributed coupons back to the user's account
          user.coupons += record.coupons_to_distribute;
          await user.save();

          // Delete the record from Coupondistribution table
          await coupondistribution.destroy({ where: { id: record.id }, transaction: t });
        }
      }
    });

    return res.status(200).json({ message: 'Coupons revoked successfully' });
  } catch (error) {
    console.error('Error revoking coupons:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/distributetousers', async (req, res) => {
  try {
    const { UIds } = req.body;

    const users = await Users.findAll({ where: { UId: UIds } });

    if (!users || users.length === 0) {
      return res.status(404).json({ error: 'Users not found' });
    }

    const totalCouponsToDistribute = await coupondistribution.sum('coupons_to_distribute');

    if (totalCouponsToDistribute === null || totalCouponsToDistribute === 0) {
      return res.status(400).json({ error: 'No coupons to distribute' });
    }

    const couponsPerUser = totalCouponsToDistribute / UIds.length;

    if (!Number.isInteger(couponsPerUser)) {
      return res.status(400).json({ error: 'Cannot equally distribute coupons among the specified users' });
    }

    await sequelize.transaction(async (t) => {
      for (const user of users) {
        user.coupons += couponsPerUser;
        await user.save();
      }

      await coupondistribution.destroy({ where: {}, transaction: t });
    });

    return res.status(200).json({ message: 'Coupons distributed equally successfully' });
  } catch (error) {
    console.error('Error distributing coupons equally:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.get('/TSL', async (req, res) => {
  try {
    const users = await Users.findAll({
      attributes: ['DOJ', 'firstName', 'secondName', 'UId', 'coupons', 'email', 'phone', 'ban'],
      order: [['UserId', 'ASC']], // Order by UId in ascending order
           where: {
       UId: { [Op.lt]: 11 }, // Start from UId 11
      },
    });

    const totalCoupons = users.reduce((sum, user) => sum + user.coupons, 0);

    res.json({ users, totalCoupons });

   // res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
const ExcelJS = require('exceljs');
const groupmembers = require('../model/groupmembers');

router.get('/download', async (req, res) => {
  try {
    const UIds = req.query.UIds;
 
    if (!Array.isArray(UIds) || UIds.length === 0) {
      return res.status(400).json({ message: 'Invalid input. Please provide a non-empty array of UIds.' });
    }

    // Fetch the distribution details for each user
    const userDistributionDetails = await Promise.all(UIds.map(async (UId) => {
      const latestDistributionRecord = await Distribution.findOne({
        attributes: ['firstName', 'secondName', 'UId', 'distributed_coupons', 'description', 'distribution_time'],
        where: { UId },
        order: [['distribution_time', 'DESC']],
      });

      if (!latestDistributionRecord) {
        return { message: `Distribution details not found for UId: ${UId}` };
      }

      const bankDetails = await BankDetails.findOne({
        attributes: ['AadarNo', 'IFSCCode', 'branchName', 'accountName', 'accountNo'],
        where: { UId },
      });

      return {
        firstName: latestDistributionRecord.firstName,
        secondName: latestDistributionRecord.secondName,
        UId: latestDistributionRecord.UId,
        distributed_coupons: latestDistributionRecord.distributed_coupons,
        description: latestDistributionRecord.description,
        distribution_time: latestDistributionRecord.distribution_time,
        AadarNo: bankDetails.AadarNo,
        IFSCCode: bankDetails.IFSCCode,
        branchName: bankDetails.branchName,
        accountName: bankDetails.accountName,
        accountNo: bankDetails.accountNo,
      };
    }));

    // Create a new workbook and worksheet
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Distribution Details');

    // Add headers to the worksheet
    worksheet.addRow([
      'First Name',
      'Second Name',
      'UId',
      'Distributed Coupons',
      'Description',
      'Distribution Time',
      'AadarNo',
      'IFSCCode',
      'Branch Name',
      'Account Name',
      'Account No',
    ]);

    // Add data to the worksheet
    userDistributionDetails.forEach(user => {
      worksheet.addRow([
        user.firstName,
        user.secondName,
        user.UId,
        user.distributed_coupons,
        user.description,
        user.distribution_time,
        user.AadarNo,
        user.IFSCCode,
        user.branchName,
        user.accountName,
        user.accountNo,
      ]);
    });

    // Set response headers for Excel download
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=DistributionDetails.xlsx');

    // Stream the workbook to the response
    await workbook.xlsx.write(res);
    res.end();

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/meditator', async (req, res) => {
  try {
    const users = await Users.findAll({
      attributes: ['DOJ', 'firstName', 'secondName', 'UId', 'coupons', 'email', 'phone', 'ban'],
      order: [['UserId', 'ASC']], // Order by UId in ascending order
           where: {
       UId: { [Op.gte]: 11 }, // Start from UId 11
      },
    });

    const totalCoupons = users.reduce((sum, user) => sum + user.coupons, 0);

    res.json({ users, totalCoupons });

   // res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/simulation', async (req, res) => {
  try {
    const { coupons, UIds, description } = req.body;

    // Validate input
    if (!coupons || !UIds || !Array.isArray(UIds) || UIds.length === 0) {
      return res.status(400).json({ message: 'Invalid input. Please provide coupons and a non-empty array of UIds.' });
    }

    // Check if coupons is a positive integer
    if (!Number.isInteger(coupons) || coupons <= 0) {
      return res.status(400).json({ message: 'Invalid input. Coupons should be a positive integer.' });
    }

    // Fetch users to update from the Users table based on UIds
    const usersToUpdate = await Users.findAll({
      where: {
        UId: UIds,
      },
    });

    // Check if enough coupons are available for all specified users
    if (usersToUpdate.length !== UIds.length) {
      return res.status(400).json({ message: 'Not enough coupons available for all specified users.' });
    }

    // Use Promise.all to asynchronously update multiple users and fetch related information
    const updatedUsers = await Promise.all(usersToUpdate.map(async (user) => {
      // Update the 'mahadhanam' table with distribution details
      await mahadhanam.create({
        firstName: user.firstName,
        secondName: user.secondName,
        UId: user.UId,
        distributed_coupons: coupons,
        description: description,
        distribution_time: new Date().toISOString(),
      });

      // Find the latest distribution record for the user from the 'Distribution' table
      const latestDistributionRecord = await mahadhanam.findOne({
        attributes: ['firstName', 'secondName', 'UId', 'distributed_coupons', 'description', 'distribution_time'],
        where: { UId: user.UId },
        order: [['distribution_time', 'DESC']], // Order by distribution_time in descending order to get the latest record
      });

      // Find bank details for the user from the 'BankDetails' table
      const bankDetails = await BankDetails.findOne({
        attributes: ['AadarNo', 'IFSCCode', 'branchName', 'accountName', 'accountNo'],
        where: { UId: user.UId },
      });

      // Return an object containing updated user details, distribution details, and bank details
      return {
        firstName: latestDistributionRecord.firstName,
        secondName: latestDistributionRecord.secondName,
        UId: latestDistributionRecord.UId,
        distributed_coupons: latestDistributionRecord.distributed_coupons,
        description: latestDistributionRecord.description,
        distribution_time: latestDistributionRecord.distribution_time,
        AadarNo: bankDetails.AadarNo,
        IFSCCode: bankDetails.IFSCCode,
        branchName: bankDetails.branchName,
        accountName: bankDetails.accountName,
        accountNo: bankDetails.accountNo,
      };
    }));

    // Send a JSON response with a success message and updated user details
    res.json({ message: 'Coupons reduced successfully for specified users.', distributionDetails: updatedUsers });
  } catch (error) {
    // Handle errors by logging and sending a 500 Internal Server Error response
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/mahadhanam-download', async (req, res) => {
  try {
    const UIds = req.query.UIds;
 
    if (!Array.isArray(UIds) || UIds.length === 0) {
      return res.status(400).json({ message: 'Invalid input. Please provide a non-empty array of UIds.' });
    }

    // Fetch the distribution details for each user
    const userDistributionDetails = await Promise.all(UIds.map(async (UId) => {
      const latestDistributionRecord = await mahadhanam.findOne({
        attributes: ['firstName', 'secondName', 'UId', 'distributed_coupons', 'description', 'distribution_time'],
        where: { UId },
        order: [['distribution_time', 'DESC']],
      });

      if (!latestDistributionRecord) {
        return { message: `Distribution details not found for UId: ${UId}` };
      }

      const bankDetails = await BankDetails.findOne({
        attributes: ['AadarNo', 'IFSCCode', 'branchName', 'accountName', 'accountNo'],
        where: { UId },
      });

      return {
        firstName: latestDistributionRecord.firstName,
        secondName: latestDistributionRecord.secondName,
        UId: latestDistributionRecord.UId,
        distributed_coupons: latestDistributionRecord.distributed_coupons,
        description: latestDistributionRecord.description,
        distribution_time: latestDistributionRecord.distribution_time,
        AadarNo: bankDetails.AadarNo,
        IFSCCode: bankDetails.IFSCCode,
        branchName: bankDetails.branchName,
        accountName: bankDetails.accountName,
        accountNo: bankDetails.accountNo,
      };
    }));

    // Create a new workbook and worksheet
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Distribution Details');

    // Add headers to the worksheet
    worksheet.addRow([
      'First Name',
      'Second Name',
      'UId',
      'Distributed Coupons',
      'Description',
      'Distribution Time',
      'AadarNo',
      'IFSCCode',
      'Branch Name',
      'Account Name',
      'Account No',
    ]);

    // Add data to the worksheet
    userDistributionDetails.forEach(user => {
      worksheet.addRow([
        user.firstName,
        user.secondName,
        user.UId,
        user.distributed_coupons,
        user.description,
        user.distribution_time,
        user.AadarNo,
        user.IFSCCode,
        user.branchName,
        user.accountName,
        user.accountNo,
      ]);
    });

    // Set response headers for Excel download
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=DistributionDetails.xlsx');

    // Stream the workbook to the response
    await workbook.xlsx.write(res);
    res.end();

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


router.get('/complexfilter', async (req, res) => {
  const { field, operator, value, logicalOperator } = req.query;

  if (!field || !operator || !value) {
    return res.status(400).json({ error: 'Field, operator, and value are required' });
  }

  try {
    console.log('Received query parameters:', { field, operator, value, logicalOperator });

    // Ensure all arrays have the same length
    if (
      !(field instanceof Array) ||
      !(operator instanceof Array) ||
      !(value instanceof Array) ||
      field.length !== operator.length ||
      operator.length !== value.length
    ) {
      return res.status(400).json({ error: 'Invalid query parameters' });
    }

    // Convert string values to numbers
    const numericValues = value.map((v) => Number(v));

    // Check if conversion was successful
    if (numericValues.some((v) => isNaN(v))) {
      return res.status(400).json({ error: 'Invalid numeric value in query parameters' });
    }

    // Constructing a Sequelize query
    const whereClauses = field.map((f, index) => ({
      [f]: {
        [Op[operator[index]]]: numericValues[index],
      },
    }));

    const sequelizeQuery = logicalOperator && logicalOperator.toUpperCase() === 'AND'
      ? { [Op.and]: whereClauses }
      : { [Op.or]: whereClauses };

    console.log('Constructed Sequelize query:', sequelizeQuery);

    const results = await Users.findAll({
      where: {
        ...sequelizeQuery, // Spread the conditions directly
      },
    });

    res.json(results);
  } catch (error) {
    console.error('Error executing query:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/execute-query', async (req, res) => {
  try {
    const queryConditions = req.body.queryConditions;
    const page = req.body.page || 1; // Default to page 1 if not provided
    const pageSize = req.body.pageSize || 10; // Default page size to 10 if not provided

    console.log(queryConditions);

    if (!queryConditions || !Array.isArray(queryConditions) || queryConditions.length === 0) {
      return res.status(400).json({ message: 'Invalid query conditions provided.' });
    }

    function isNumeric(num) {
      return !isNaN(num);
    }

    let sql = "SELECT * FROM sequel.users WHERE ";
    for (let i = 0; i < queryConditions.length; i++) {
      sql += `${queryConditions[i].field} ${queryConditions[i].operator} ${isNumeric(queryConditions[i].value) ? queryConditions[i].value : `'${queryConditions[i].value}'` } ${queryConditions[i].logicaloperator != "null" ? queryConditions[i].logicaloperator : "" } `;
    }

    // Apply pagination
    const offset = (page - 1) * pageSize;
    sql += `LIMIT ${pageSize} OFFSET ${offset}`;

    console.log(sql);

    const results = await sequelize.query(sql);
    console.log(results[0]);
    
    // Assuming sequelize returns an array of rows in the first element of the results array
    res.json({ results: results[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});



// router.post('/execute-query', async (req, res) => {
//   try {
//     const query = req.body.queryConditions;
//     console.log(query);

//     if (!query || !Array.isArray(query) || query.length === 0) {
//       return res.status(400).json({ message: 'Invalid query conditions provided.' });
//     }
//     function isNumeric(num){
//       return !isNaN(num)
//     }

//     let sql = "SELECT * FROM sequel.users WHERE "
//     for (let i = 0; i < query.length; i++) {
//     sql += `${query[i].field} ${query[i].operator} ${isNumeric(query[i].value) ? query[i].value : `'${query[i].value}'` } ${query[i].logicaloperator != "null" ? query[i].logicaloperator : "" } `
//     }

//     console.log(sql);

//     const results = await sequelize.query(sql);
//     console.log(results[0]);
//     res.json({ results: results[0] });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: 'Internal server error.' });
//   }
// });

router.post('/save-token', async (req, res) => {
  try {
    const { UId, token } = req.body; 
    const newNotification = await notification.create({ UId, token });
    res.status(201).json({ message: 'Notification saved successfully', notification: newNotification });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/broadcast-messages', async (req, res) => {
  try {
    const { Broadcast_message, time, priority, title, body } = req.body;

    // Check if message, time, and priority are provided
    if (!Broadcast_message || !time || !priority) {
      return res.status(400).json({ error: 'Message, time, and priority are required' });
    }

    // Create a broadcast message record in the database
    await Broadcast.create({
      Broadcast_message,
      time,
      priority
    });

    // Fetch all tokens from the notification table
    const notifications = await Notification.findAll();
    
    // Send notifications to each token
    const sendPromises = notifications.map(async (notification) => {
      const message = {
        notification: {
          title,
          body,
        },
        token: notification.token,
      };
      
      return admin.messaging().send(message);
    });

    // Wait for all notifications to be sent
    await Promise.all(sendPromises);

    res.status(200).json({ message: 'Broadcast messages sent successfully' });

  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


///////////////////////////////////////////////////////// configarations///////////////////////////////////////
router.get('/financialconfig', async (req,res) => {
  try {
     // console.log("get financialconfig data");
      const finconfig = await financialconfig.findAll();
      
      res.status(200).json({message:'Fetching data successfully',finconfig});
  } catch(error) {
      //console.log(error);
      res.status(500).json({message:'An error occurred while fetching data'});
  }
});

router.put('/update-finconfig/:id', async (req, res) => {
  const id = req.params.id;
  const configdata = req.body;

  try {
      if (!id) {
          return res.status(400).json({ error: 'ID not found' });
      }

      // Find by id
      const data = await financialconfig.findOne({ where: { id } });

      // Update data
      if (data) {
         // console.log("finconfig data updated");
          await data.update(configdata);
          return res.status(200).json({ message: 'Data updated successfully' });
          
      } else {
          return res.status(404).json({ error: 'Data not found' });
      }
  } catch (error) {
      //console.log(error);
      return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.get('/appconfig',async(req,res) =>{
  try{
      //console.log("get appconfig data");
      const appconfig = await applicationconfig.findAll();
      
      res.status(200).json({message:'Fetching data successfully',appconfig});
  } catch(error) {
      //console.log(error);
      res.status(500).json({message:'internal server error'});
  }
});

router.put('/update-appconfig/:id', async(req, res) =>{
  const id = req.params.id;
  const configdata = req.body;

  try{
      if(!id) {
          return res.status(400).json({error:'ID not found'});
      }
      // find by id
      const data = await applicationconfig.findOne({where:{id}});

      //updating
      if(data){
         // console.log("updating");
          await data.update(configdata);
          return res.status(200).json({message:'Data updated successfully'});
      } else {
          return res.status(404).json({ error:'Data not found'});
      }
  } catch(error) {
     // console.log(error);
      return res.status(500).json({error:'internal server error'});
  }
});

router.get('/support',async(req,res) =>{
  try{
     // console.log('get support');
      const support = await supportcontact.findAll();
      res.status(200).json({message:'Fetching data successfully',support});

  } catch (error) {
      //console.log(error);
      res.status(500).json({message:'internal server error'});
  }
});

router.put('/update-support/:id', async (req, res) => {
  const id = req.params.id;
  const usersdata = req.body;

  try {
      if (!id) {
          return res.status(400).json({ error: 'Invalid request, missing ID' });
      }

      // Find the support contact by ID
      const data = await supportcontact.findOne({ where: { id } });

      if (data) {
          // Update the support contact data
          await data.update(usersdata);

          return res.status(200).json({ message: 'Data updated successfully' });
      } else {
          return res.status(404).json({ error: 'Support contact not found' });
      }
  } catch (error) {
      //console.error(error); 

      return res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});
////////////////////////////////// financial pages////////////////////////////////

router.get('/list-users', async (req, res) => {
  try {
    // Step 1: Fetch the list of users
    const usersList = await Users.findAll({
      attributes: ['DOJ', 'firstName', 'secondName', 'UId', 'coupons', 'email', 'phone', 'Level', 'node_number'],
    });

    // Extract UIds from the usersList
    const UIds = usersList.map(user => user.UId);

    // Step 2: Fetch the total sum of distributed_coupons for each UId
    const distributionResults = await Distribution.findAll({
      where: { UId: { [Op.in]: UIds } },
      attributes: ['UId', [sequelize.fn('sum', sequelize.col('distributed_coupons')), 'total_distributed_coupons']],
      group: ['UId'],
    });

    // Step 3: Merge the results and send the response
    const mergedResults = usersList.map(user => {
      const distributionResult = distributionResults.find(result => result.UId === user.UId);
      return {
        ...user.dataValues,
        total_distributed_coupons: distributionResult ? distributionResult.dataValues.total_distributed_coupons : 0,
      };
    });

    res.json({ users: mergedResults });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
router.post('/financial-query', async (req, res) => {
  try {
    const query = req.body.queryConditions;

    if (!query || !Array.isArray(query) || query.length === 0) {
      return res.status(400).json({ message: 'Invalid query conditions provided.' });
    }

    function isNumeric(num) {
      return !isNaN(num);
    }

    let sql = "SELECT * FROM sequel.users WHERE ";

    for (let i = 0; i < query.length; i++) {
      sql += `${query[i].field} ${query[i].operator} ${isNumeric(query[i].value) ? query[i].value : `'${query[i].value}'`} ${query[i].logicaloperator != "null" ? query[i].logicaloperator : ""} `;
    }

    console.log(sql);

    const userResults = await sequelize.query(sql);

    const UIds = userResults[0].map(user => user.UId);

    const distributionResults = await Distribution.findAll({
      where: { UId: { [Op.in]: UIds } },
      attributes: ['UId', [sequelize.fn('sum', sequelize.col('distributed_coupons')), 'total_distributed_coupons']],
      group: ['UId'],
    });

    const mergedResults = userResults[0].map(user => {
      const distributionResult = distributionResults.find(result => result.UId === user.UId);
      return {
        ...user,
        total_distributed_coupons: distributionResult ? distributionResult.dataValues.total_distributed_coupons : 0,
      };
    });

    res.json({ results: mergedResults });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});
router.get('/search', async (req, res) => {
  try {
    const field = req.query.field; 
    const value = req.query.value; 

    if (!field || !value) {
      return res.status(400).json({ message: 'Please provide both field and value parameters' });
    }

    const userDetails = await Users.findAll({
      where: {
        [field]: value,
      },
    });

    if (!userDetails || userDetails.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Step 2: Extract UIds from the search results
    const UIds = userDetails.map(user => user.UId);

    // Step 3: Fetch the total sum of distributed_coupons for each UId
    const distributionResults = await Distribution.findAll({
      where: { UId: { [Op.in]: UIds } },
      attributes: ['UId', [sequelize.fn('sum', sequelize.col('distributed_coupons')), 'total_distributed_coupons']],
      group: ['UId'],
    });

    // Step 4: Merge the user details with the distribution results
    const mergedResults = userDetails.map(user => {
      const distributionResult = distributionResults.find(result => result.UId === user.UId);
      return {
        ...user.dataValues,
        total_distributed_coupons: distributionResult ? distributionResult.dataValues.total_distributed_coupons : 0,
      };
    });

    res.json({ message: 'Success', data: mergedResults });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
////////////////////////////appointments/////////////////////////////////

router.get('/list-all-appointment', async (req, res) => {
  try {
    // Find all appointments
    const appointments = await Appointment.findAll();

    // Fetch group members and coupons for each appointment
    const appointmentsWithGroupMembersAndCoupons = [];
    for (const appointment of appointments) {
      const groupMembers = await GroupMembers.findAll({ where: { appointmentId: appointment.id } });
      const user = await Users.findOne({ where: { UId: appointment.UId }, attributes: ['coupons'] });

      // Create a merged object for each appointment
      const mergedAppointmentData = {
        appointment,
        groupMembers,
        user // Only includes coupon-related data
      };

      appointmentsWithGroupMembersAndCoupons.push(mergedAppointmentData);
    }

    // Respond with the list of merged appointment data
    return res.status(200).json({ message: 'Fetching appointments', appointments: appointmentsWithGroupMembersAndCoupons });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


router.get('/list-appointment/:id', async (req, res) => {
  const { id } = req.params;

  try {
    // Find appointment by ID
    const appointment = await Appointment.findOne({ where: { id } });

    if (!appointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    // Find group members for the appointment
    const groupMembers = await GroupMembers.findAll({ where: { appointmentId: appointment.id } });

    // Attach group members to the appointment object
    appointment.dataValues.groupMembers = groupMembers;

    // Respond with the appointment
    return res.status(200).json({ message: 'Fetching appointment', appointment });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.put('/update-payment/:id', upload.single('appointmentImage'), async (req, res) => {

  //console.log('update')
  const id = req.params.id;
  const appointmentData = req.body;
  const appointmentImageFile = req.file;

  try {
      // Check if the user is authenticated
      if (!id) {
          return res.status(401).json({ error: 'Unauthorized' });
      }

      // Find the appointment by id
      const appointment = await Appointment.findOne({ where: { id } }); // Corrected variable name

      // Update appointment details
      if (appointment) {
          // Update all fields provided in the request, excluding the appointmentImage field
          delete appointmentData.appointmentImage; // Remove appointmentImage from appointmentData
          await appointment.update(appointmentData);

          // Store or update appointment image
          let appointmentImageUrl = appointment.imageUrl; // Default to current URL
          if (appointmentImageFile) {
              const appointmentImagePath = `appointment_images/${id}/${appointmentImageFile.originalname}`;

              // Upload new appointment image to Firebase Storage
              await storage.upload(appointmentImageFile.path, {
                  destination: appointmentImagePath,
                  metadata: {
                      contentType: appointmentImageFile.mimetype
                  }
              });

              // Get the URL of the uploaded appointment image
              appointmentImageUrl = `gs://${storage.name}/${appointmentImagePath}`;
//console.log(appointmentImageUrl);
              // Delete the current appointment image from Firebase Storage
              if (appointment.imageUrl) {
                  const currentAppointmentImagePath = appointment.imageUrl.split(storage.name + '/')[1];
                  await storage.file(currentAppointmentImagePath).delete();
              }
          }

          // Update appointment's imageUrl in appointment table
          await appointment.update({ imageUrl: appointmentImageUrl });

          return res.status(200).json({ message: 'Appointment details updated successfully' });
      } else {
          return res.status(404).json({ error: 'Appointment not found' });
      }
  } catch (error) {
      //console.error(error);
      return res.status(500).json({ error: 'Internal Server Error' });
  }
});


router.put('/discount/:UId', async (req, res) => {
  const { UId } = req.params;
  const { coupon, id } = req.body;

  try {
    // Check if UId is a valid integer
    if (isNaN(parseInt(UId))) {
      return res.status(400).json({ error: 'Invalid User ID' });
    }

    // Check if coupon is numeric
    if (isNaN(parseInt(coupon))) {
      return res.status(400).json({ error: 'Coupon amount must be a number' });
    }

    const user = await Users.findOne({ where: { UId } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const totalCoupons = user.coupons;
    if (coupon > totalCoupons) {
      return res.status(400).json({ error: 'Invalid coupon amount' });
    }

    const updatedTotalCoupons = totalCoupons - coupon;
    await Users.update({ coupons: updatedTotalCoupons }, { where: { UId } });

    // Assuming 'appointment' is a model with a proper 'where' condition for the update
    await Appointment.update({ discount: coupon * 2500 }, { where: { id } });

    return res.status(200).json({ message: 'Discount updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


const ApplicationConfig = require('../model/applicationConfig')
router.put('/update-gurujidate', async (req, res) => {
  try {
    console.log('Updating');
    const id = 11;
    const {  values } = req.body;
    console.log(req.body.values)

    // Find the existing record by ID
    let config = await ApplicationConfig.findByPk(id);

    // If the record doesn't exist, create a new one
    if (!config) {
      config = await ApplicationConfig.create({ id });
    }

    // Convert the array of values to JSON format and update the record
    config.value = JSON.stringify(values);
    await config.save();

    return res.status(200).json({ message: 'Application config updated successfully' });
  } catch (error) {
    console.error('Error updating application config:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/appointment-query', async (req, res) => {
  try {
    const queryConditions = req.body.queryConditions;
    const page = req.body.page || 1; // Default to page 1 if not provided
    const pageSize = req.body.pageSize || 10; // Default page size to 10 if not provided

    console.log(queryConditions);

    if (!queryConditions || !Array.isArray(queryConditions) || queryConditions.length === 0) {
      return res.status(400).json({ message: 'Invalid query conditions provided.' });
    }

    function isNumeric(num) {
      return !isNaN(num);
    }

    let sql = "SELECT * FROM sequel.appointments WHERE ";
    for (let i = 0; i < queryConditions.length; i++) {
      sql += `${queryConditions[i].field} ${queryConditions[i].operator} ${isNumeric(queryConditions[i].value) ? queryConditions[i].value : `'${queryConditions[i].value}'` } ${queryConditions[i].logicaloperator != "null" ? queryConditions[i].logicaloperator : "" } `;
    }

    // Apply pagination
    const offset = (page - 1) * pageSize;
    sql += `LIMIT ${pageSize} OFFSET ${offset}`;

    console.log(sql);

    const results = await sequelize.query(sql);
    console.log(results[0]);
    
    // Assuming sequelize returns an array of rows in the first element of the results array
    res.json({ results: results[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

module.exports = router;
