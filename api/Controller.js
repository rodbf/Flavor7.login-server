const dao = require('../db/DAO');
const parser = require('../db/Parser');
const argon2 = require('argon2');
const jwt = require('../jwt/jwt');
const fs = require('fs');
const crypto = require('crypto');
var base64url = require('base64url');
//const db = require('../db/DBEnum');

function sendJSON(res, result){
    //console.log(result);
    res.json(result);
}

exports.authenticateFromCredentials = (req, res) => {
    dao.getUserByLogin(req.body.login, (err, result) => {
        let ret = {};

        if(err){
            console.log(err);
        }
        else if (result.length == 0){
            ret.RES_CODE = 10001
            ret.RES_MSG = "Login inválido";
            sendJSON(res, ret);
        }
        else {
            validatePassword(result[0].PASSWORD, req.body.pass, (valid) => {
                if(!valid){
                    ret.RES_CODE = 10004;
                    ret.RES_MSG = "Senha errada";
                }
                else{
                    user = result[0].ID_USER;
                    state = result[0].STATE;
                    
                    if (state == 1){
                        ret.RES_CODE = 10000;
                        ret.RES_MSG = "Login";
                        ret.AUTH = createJWT(result[0].ID_USER, result[0].ACCOUNT_TYPE);
                        ret.USER_ID = result[0].ID_USER;
                        ret.ACCOUNT_TYPE = result[0].ACCOUNT_TYPE;
                        ret.DISPLAY_NAME = result[0].DISPLAY_NAME;
                        ret.EMAIL = result[0].EMAIL;
                    }
                    else if (state == 2){
                        ret.RES_CODE = 10002;
                        ret.RES_MSG = "Sua senha foi mudada";
                    }
                }
                sendJSON(res, ret);
            });
        }
    });
}

exports.authenticateFromToken = (req, res) => {
    let ret = {};
    let token = req.body.jwt;
    let verify = jwt.verify(token);
    if(verify == "verified" || verify == "jwt expired"){
        let payload = jwt.decode(token).payload;
        let refresh = payload.refresh;
        let user = payload.sub;
        let accountType = payload.acc_type
        if(verify == "verified"){
            ret.RES_CODE = 10000;
            ret.RES_MSG = "Login";
            ret.AUTH = token;
            ret.USER = user;
            ret.ACCOUNT_TYPE = accountType;
            sendJSON(res, ret);
        }
        else{
            dao.findRefreshToken(user, refresh, found => {
                if(!found){
                    ret.RES_CODE = 10005;
                    ret.RES_MSG = "Invalid session";
                }
                else{
                    ret.RES_CODE = 10000;
                    ret.RES_MSG = "Login";
                    ret.AUTH = refreshJWT(user, accountType, refresh);
                    ret.USER = user;
                    ret.ACCOUNT_TYPE = accountType;
                }
                sendJSON(res, ret);
            })
        }
    }
    else{
        ret.RES_CODE = 10011;
        ret.RES_MSG =  "Invalid session";
        sendJSON(res, ret);
    }
}

function createJWT(user, accountType){
    signOptions = {
        subject: user+""
    };
    refresh = base64url(crypto.randomBytes(20));
    payload = {
        refresh: refresh,
        acc_type: accountType+""
    };
    dao.insertRefreshToken(user, refresh);

    return jwt.sign(payload, signOptions);
}

function refreshJWT(user, accountType, refresh){
    signOptions = {
        subject: user+""
    };
    payload = {
        refresh: refresh,
        acc_type: accountType+""
    };

    return jwt.sign(payload, signOptions);
}


async function validatePassword(hash, pass, callback){
    try{
        callback(await argon2.verify(hash, pass));/*
        if(await argon2.verify(hash, pass)){
            callback(true);
        }
        else{
            callback(false);
        }*/
    }
    catch(err){
        callback(false);
        console.log(err);
    }
}

exports.createAccount = (req, res) => {
    ret = {};
    user = req.body.login;
    pass = req.body.pass;
    display = req.body.display;
    hashPassword(pass, (hash) => {
        if (!hash) {
            ret.RES_CODE = 10006;
            ret.RES_MSG = "Internal error";
            sendJSON(res, ret);
        }
        else {
            dao.createAccount(user, hash, display, result => {
                ret.RES_CODE = result.RES_CODE;
                if (result.RES_CODE == 10010){
                    ret.RES_MSG = "Cadastro bem sucedido";
                    dao.getUserByLogin(user, (err, user) => {
                        console.log(err, user);
                        ret.AUTH = createJWT(user[0].ID_USER, user[0].ACCOUNT_TYPE);
                        ret.USER_ID = user[0].ID_USER;
                        ret.ACCOUNT_TYPE = user[0].ACCOUNT_TYPE;
                        ret.DISPLAY_NAME = user[0].DISPLAY_NAME;
                        ret.EMAIL = user[0].EMAIL;
                        sendJSON(res, ret);
                    });
                    return;
                }
                else if (result.RES_CODE == 10007)
                    ret.RES_MSG = "Email já existe";
                else if (result.RES_CODE == 10008)
                    ret.RES_MSG = "Nome já existe";
                else if (result.RES_CODE == 10009)
                    ret.RES_MSG = "Nome e email já existem";
                sendJSON(res, ret);
            });
        }
    });
}

async function hashPassword(pass, callback){
    try{
        callback(await argon2.hash(pass));
    }
    catch(err){
        console.log(err)
        callback(false);
    }
}

function login(user, pass, callback){
    dao.getUserByLogin(user, (err, result) => {
        let ret = {};

        if(err){
            console.log(err);
        }
        else if (result.length == 0){
            ret.RES_CODE = 10001
            ret.RES_MSG = "Login inválido";
            callback(ret);
        }
        else {
            validatePassword(result[0].PASSWORD, pass, (valid) => {
                if(!valid){
                    ret.RES_CODE = 10004;
                    ret.RES_MSG = "Senha errada";
                }
                else{
                    user = result[0].ID_USER;
                    state = result[0].STATE;
                    
                    if (state == 1){
                        ret.RES_CODE = 10000;
                        ret.RES_MSG = "Login";
                        ret.AUTH = createJWT(result[0].ID_USER, result[0].ACCOUNT_TYPE);
                        ret.USER_ID = result[0].ID_USER;
                        ret.ACCOUNT_TYPE = result[0].ACCOUNT_TYPE;
                        ret.DISPLAY_NAME = result[0].DISPLAY_NAME;
                    }
                    else if (state == 2){
                        ret.RES_CODE = 10002;
                        ret.RES_MSG = "Sua senha foi mudada";
                    }
                }
                callback(ret);
            });
        }
    });
}

exports.authorize = (req, res) => {
    let ret = {};
    let token = req.body.jwt;
    let verify = jwt.verify(token);

    if(verify == "verified" || verify == "jwt expired"){
        let payload = jwt.decode(token).payload;
        let refresh = payload.refresh;
        let user = payload.sub;
        let accountType = payload.acc_type
        if(verify == "verified"){
            ret.RES_CODE = 10012;
            ret.RES_MSG = "Verified";
            ret.USER = user;
            ret.AUTH = token;
            sendJSON(res, ret);
        }
        else{
            dao.findRefreshToken(user, refresh, found => {
                if(!found){
                    ret.RES_CODE = 10005;
                    ret.RES_MSG = "Invalid session";
                }
                else{
                    ret.RES_CODE = 10012;
                    ret.RES_MSG = "Verified";
                    ret.USER = user;
                    ret.AUTH = refreshJWT(user, accountType, refresh);
                }
                sendJSON(res, ret);
            })
        }
    }
    else{
        ret.RES_CODE = 10011;
        ret.RES_MSG =  "Invalid session";
        sendJSON(res, ret);
    }
}