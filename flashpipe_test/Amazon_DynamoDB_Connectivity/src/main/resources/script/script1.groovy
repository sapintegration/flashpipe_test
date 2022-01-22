import com.sap.gateway.ip.core.customdev.util.Message;
import java.util.HashMap;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
def Message processData(Message message) {
    //************* REQUEST VALUES *************
    String method = 'POST';
    String service = 'dynamodb';
    String host = 'dynamodb.ap-southeast-2.amazonaws.com';
    String region = 'ap-southeast-2';
    String endpoint = 'https://dynamodb.ap-southeast-2.amazonaws.com/';
    // POST requests use a content type header. For DynamoDB, the content is JSON.
    String content_type = 'application/x-amz-json-1.0';
    // DynamoDB requires an x-amz-target header that has this format:DynamoDB_<API version>.<operationName>
    String amz_target = 'DynamoDB_20120810.PutItem';

    // Request parameters for Create/Update new item--passed in a JSON block.
    String body = message.getBody(java.lang.String) as String;
    String request_parameters = body;
    
    // Read AWS access key from security artifacts. Best practice is NOT to embed credentials in code.
    String access_key = '<Your AWS Access Key';
    String secret_key = '<Your AWS Secret Key';
  
    // Create a date for headers and the credential string
    def date = new Date();
    DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));//server timezone
    String amz_date = dateFormat.format(date);
    dateFormat = new SimpleDateFormat("yyyyMMdd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));//server timezone
    String date_stamp = dateFormat.format(date);
    
    // ************* TASK 1: CREATE A CANONICAL REQUEST *************
    // http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    
    // Step 1 is to define the verb (GET, POST, etc.)--already done.
    
    // Step 2: Create canonical URI--the part of the URI from domain to query 
    // string (use '/' if no path)
    String canonical_uri = '/';
    
    // Step 3: Create the canonical query string. In this example, request
    // parameters are passed in the body of the request and the query string is blank.
    String canonical_querystring = '';
    
    // Step 4: Create the canonical headers. Header names must be trimmed
    // and lowercase, and sorted in code point order from low to high. Note that there is a trailing \n.
    String canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-target:' + amz_target + '\n';
    
    // Step 5: Create the list of signed headers. This lists the headers
    // in the canonical_headers list, delimited with ";" and in alpha order.
    // Note: The request can include any headers; canonical_headers and
    // signed_headers include those that you want to be included in the
    // hash of the request. "Host" and "x-amz-date" are always required.
    // For DynamoDB, content-type and x-amz-target are also required.
    String signed_headers = 'content-type;host;x-amz-date;x-amz-target';
    
    // Step 6: Create payload hash. In this example, the payload (body of the request) contains the request parameters.
    String payload_hash = generateHex(request_parameters);
    
    // Step 7: Combine elements to create canonical request
    String canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash;
    
    // ************* TASK 2: CREATE THE STRING TO SIGN*************
    // Match the algorithm to the hashing algorithm you use, either SHA-1 or SHA-256 (recommended)
    String algorithm = 'AWS4-HMAC-SHA256';
    String credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request';
    String string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  generateHex(canonical_request);
    
    // ************* TASK 3: CALCULATE THE SIGNATURE *************
    // Create the signing key using the function defined above.
    byte[] signing_key = getSignatureKey(secret_key, date_stamp, region, service);
    
    // Sign the string_to_sign using the signing_key
    byte[] signature = HmacSHA256(string_to_sign,signing_key);
    
     /* Step 3.2.1 Encode signature (byte[]) to Hex */
    String strHexSignature = bytesToHex(signature);
    
    // ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    // Put the signature information in a header named Authorization.
    String authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + strHexSignature;
    
    // For DynamoDB, the request can include any headers, but MUST include "host", "x-amz-date",
    // "x-amz-target", "content-type", and "Authorization". Except for the authorization
    // header, the headers must be included in the canonical_headers and signed_headers values, as
    // noted earlier. Order here is not significant.

    // set X-Amz-Date Header and Authorization Header
    message.setHeader("X-Amz-Date",amz_date);
    message.setHeader("Authorization", authorization_header);
      
    return message;
}

String bytesToHex(byte[] bytes) {
    char[] hexArray = "0123456789ABCDEF".toCharArray();            
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = hexArray[v >>> 4];
        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars).toLowerCase();
} 

String generateHex(String data) {
    MessageDigest messageDigest;

    messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(data.getBytes("UTF-8"));
    byte[] digest = messageDigest.digest();
    return String.format("%064x", new java.math.BigInteger(1, digest));
}

byte[] HmacSHA256(String data, byte[] key) throws Exception {
    String algorithm="HmacSHA256";
    Mac mac = Mac.getInstance(algorithm);
    mac.init(new SecretKeySpec(key, algorithm));
    return mac.doFinal(data.getBytes("UTF8"));
}

byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
    byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
    byte[] kDate = HmacSHA256(dateStamp, kSecret);
    byte[] kRegion = HmacSHA256(regionName, kDate);
    byte[] kService = HmacSHA256(serviceName, kRegion);
    byte[] kSigning = HmacSHA256("aws4_request", kService);
    return kSigning;
}