const express = require('express');
const app = express();
const body_parser = require('body-parser');
const port = 5000;

app.use(body_parser.json());

const routes = require('./api/Routes');

routes(app);

app.listen(port, () =>{
    console.log('listening at port '+port)
});