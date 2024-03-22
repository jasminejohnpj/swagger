const express = require('express');
const cors = require('cors');
const app = express();
const http = require('http');
const { Server } = require('socket.io');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express')

app.use(cors());

app.use(express.json())

app.use('/api/v1', require('./router/routing')); // Corrected the router path
const httpServer = http.createServer(app)



const io = new Server(httpServer,{cors:{origin: "*"}})

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'thasmai star life',
            version: '1.0.0',
            description: "Api document for user app",
            contact: {
                name: "Jasmine John",
                email: "jasminejohn@gmail.com"
            },
        },
    servers: [
        {
               url: "https://thasmai.tstsvc.in/api/v1/"
           // url: "http://localhost:5000/api/v1/"
        }
    ],
},
    apis: ["./controller/*.js"]
};

//comment
// Added the missing closing parenthesis here
const swaggerSpec = swaggerJSDoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));


module.exports = app