const rs = require('jsrsasign');

// Perform encryption on request
module.exports.requestHooks = [
    (context) => {
        try{
            encryptRequest(context);
        }catch (e){
            context.app.alert("Error", "Wings Encryption failed. " + e);
        }
        
    }
];

function encryptRequest(context){
    const publicKey = context.request.getEnvironmentVariable('public_key');
    const encryptProperties = context.request.getEnvironmentVariable('encryptProperties');

    let encryptedProperties = encryptProperties.split(",");
    encryptedProperties = encryptedProperties.map(prop => prop.toLowerCase());

    var encryptedRequest = JSON.parse(context.request.getBody().text,
    (key, value) =>
        encryptedProperties.includes(key.toLowerCase())
        ? encrypt(value, publicKey)
        : value
    );
    
    context.request.setBody(
        { 
            mimeType: `application/json`,
            text:  JSON.stringify(encryptedRequest),
        });


}

function encrypt(data, key){
    if(data){
        const publicKey = rs.KEYUTIL.getKey(key);
        var hexValue = rs.KJUR.crypto.Cipher.encrypt(data, publicKey, "RSAOAEP");
        return rs.hextob64(hexValue);
    }
    return data;
}

function decrypt(data, key){
    if(data){
        const privateKey = rs.KEYUTIL.getKey(key);
        var encryptedText = rs.b64tohex(data);
        return rs.KJUR.crypto.Cipher.decrypt(encryptedText, privateKey, "RSAOAEP");
    }
    return data;
}