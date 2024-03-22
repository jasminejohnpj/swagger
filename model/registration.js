require('dotenv').config();
const { DataTypes, Sequelize } = require('sequelize');
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    dialect: process.env.DB_DIALECT,
    host: process.env.DB_HOST,
    logging: false,

});
const reg = sequelize.define('reg', {
    UserId: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
      },
    first_name: { type: DataTypes.STRING,defaultValue: ''},
    last_name: { type: DataTypes.STRING,defaultValue: ''},
    DOB: { type: DataTypes.STRING,defaultValue: '' },
    gender: { type: DataTypes.STRING,defaultValue: '' },
    email: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: true
    },
    address: { type: DataTypes.STRING,defaultValue: '' },
    pincode: { type: DataTypes.INTEGER,defaultValue: 0 },
    state: { type: DataTypes.STRING ,defaultValue: ''},
    district: { type: DataTypes.STRING,defaultValue: '' },
    country: { type: DataTypes.STRING,defaultValue: '' },
    phone: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: true
    },
    reference: { type: DataTypes.STRING,defaultValue: '' },
    languages: {type:DataTypes.STRING,defaultValue: ''},
    remark: { type: DataTypes.TEXT,defaultValue: '' },
    verify: { type: DataTypes.STRING, defaultValue: 'false' },
    UId: {
        type: DataTypes.INTEGER,      
      },
    DOJ: { type: DataTypes.STRING},
    expiredDate: { type: DataTypes.DATE, allowNull: true },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
        
    },
    classAttended: { type: DataTypes.STRING, defaultValue: 'false' },
    ans : { type: DataTypes.STRING },
    isans : { type: DataTypes.BOOLEAN, defaultValue:false},
    other: { type: DataTypes.STRING},
    profilePicUrl: { type: DataTypes.STRING, allowNull: true },
    maintanance_fee: { type: DataTypes.STRING, defaultValue:'false'},
    
 });

sequelize.sync({alter: true})
    .then((data) => {
       // console.log(data);
        console.log('reg table created');
    })
    .catch((err) => {
        console.log(err);
    });


    


module.exports = { reg,sequelize };