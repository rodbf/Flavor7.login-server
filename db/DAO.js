const async = require('async');
const con = require('./Pool');

exports.getUserByLogin = (login, callback) => {
    let query = "SELECT l.ID_USER, u.EMAIL, l.STATE, l.PASSWORD, u.ACCOUNT_TYPE, u.DISPLAY_NAME FROM LOGIN l LEFT JOIN USERS u ON l.id_user = u.id WHERE u.email = ? ORDER BY creation DESC LIMIT 1";
    con.query(query, [login], (err, result) => {
        callback(err, result);
    });
}

exports.insertRefreshToken = (user, token) => {
    let query = "INSERT INTO USER_TOKENS(ID_USER, TOKEN) VALUES(?, ?)";
    con.query(query, [user, token], (err, result) =>{
        if (err)
            console.log(err);
    });
}

exports.findRefreshToken = (user, token, callback) => {
    let query = "SELECT ID_USER, TOKEN FROM USER_TOKENS WHERE ID_USER = ? AND TOKEN = ? LIMIT 1";
    con.query(query, [user, token], (err, result) =>{
        ret = false;
        if(err)
            console.log(err);
        else if(result.length > 0){
            ret = true;
            con.query("UPDATE USER_TOKENS SET LAST_USE = CURRENT_TIMESTAMP WHERE TOKEN = ?", [token]);
        }
        callback(ret);
    });
}

exports.createAccount = (user, pass, display, callback) => {
    ret = {};

    async.parallel(
        {
            user: callback => {
                const query = "SELECT id FROM users WHERE email = ?";
                con.query(query, [user], (err, result) => {
                    callback(err, result);
                });
            },
            display: callback => {
                const query = "SELECT id FROM users WHERE display_name = ?";
                con.query(query, [display], (err, result) => {
                    callback(err, result);
                });
            }
        },
        (err, results) => {
            if(results.user.length > 0 & results.display.length > 0){
                ret.RES_CODE = 10009;
                callback(ret);
            }
            else if(results.user.length > 0){
                ret.RES_CODE = 10007;
                callback(ret);
            }
            else if(results.display.length > 0){
                ret.RES_CODE = 10008;
                callback(ret);
            }
            else{
                ret.RES_CODE = 10010;
                con.query("INSERT INTO USERS(display_name, email) VALUES(?, ?)", [display, user], (err, result) => {
                    userId = result.insertId;
                    con.query("INSERT INTO login(id_user, password) VALUES(?, ?)", [userId, pass], (a, b) => {
                        callback(ret);
                    });
                });
            }
        }
    );
}

function findUser(user, callback){
    console.log("findUser");
    let query = "SELECT * FROM USERS WHERE email = ?";
    con.query(query, [user], (err, result) => {
        if (result.length > 0)
            callback(true);
        else
            callback(false);
    })
}