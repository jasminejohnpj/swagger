require('dotenv').config();
const { DataTypes, Sequelize } = require('sequelize');
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    dialect: process.env.DB_DIALECT,
    host: process.env.DB_HOST,
    logging: false,

});

const groupmembers = sequelize.define('groupmembers',{
    appointmentId:{type: DataTypes.INTEGER},
    name:{type:DataTypes.STRING},
    relation:{type:DataTypes.STRING},
    age:{type: DataTypes.STRING}
});

sequelize.sync({alter:true})
    .then((data) => {
       // console.log(data);
        console.log('groupmembers table created');
    })
    .catch((err) => {
        console.log(err);
    });
module.exports = groupmembers;