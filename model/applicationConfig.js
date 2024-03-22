require('dotenv').config();
const { DataTypes, Sequelize } = require('sequelize');
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {

    dialect: process.env.DB_DIALECT,
    host: process.env.DB_HOST,
    logging: false,

});
const applicationconfig = sequelize.define('applicationconfig',{
field:{type:DataTypes.STRING},
value:{type:DataTypes.TEXT},
},
{
    timestamps: false, 
});
sequelize.sync({alter:true})
    .then((data) => {
        console.log('Applicationconfig table created');
    })
    .catch((err) =>{
        console.log(err);
    });
    module.exports =applicationconfig