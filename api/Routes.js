module.exports = function(server){
    var controller = require('./Controller');

    server.route('/login')
        .post(controller.authenticateFromCredentials);

    server.route('/authenticate')
        .post(controller.authenticateFromToken);

    server.route('/new-account')
        .post(controller.createAccount);

    server.route('/authorize')
       .post(controller.authorize);
}