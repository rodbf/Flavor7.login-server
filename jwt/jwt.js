const fs = require('fs');
const jwt = require('jsonwebtoken');

var privateKEY = fs.readFileSync(__dirname+'\\keychain\\private.key', 'utf8');
var publicKEY = fs.readFileSync(__dirname+'\\keychain\\public.key', 'utf8');  
module.exports = {
 sign: (payload, Options) => {
  var signOptions = {
      subject:  Options.subject,
      expiresIn:  "1h",
      algorithm:  "RS256"    
  };
  return jwt.sign(payload, privateKEY, signOptions);
},
verify: (token) => {
  var verifyOptions = {
      algorithm:  ["RS256"]
  };
   try{
     if(jwt.verify(token, publicKEY, verifyOptions)){
      return "verified";
    }
   }catch (err){
     return err.message;
   }
},
 decode: (token) => {
    return jwt.decode(token, {complete: true});
    //returns null if token is invalid
 }
}