// DDB and PinPoint SDKs
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { BatchWriteCommand } from "@aws-sdk/lib-dynamodb";
import { PinpointClient, PhoneNumberValidateCommand } from "@aws-sdk/client-pinpoint";

// Declaring clients outside Lambda handler for connection reuse
const ddbClient = new DynamoDBClient({});
const ppClient = new PinpointClient({});

// DynamoDB parameters
const IP_DDB_TABLE_NAME = 'sms-pumping-ip-table'; // name of the table used to check velocity of requests per ip
const PHONE_DDB_TABLE_NAME = 'sms-pumping-phone-table'; // name of the table used to check velocity of requests per phone / phone prefix
const DDB_ITEM_TTL = 604800; // 7 days afterwich created items in DDB are deleted to save storage
const DDB_CALL_TIMEOUT = 500; // Timeout on calls to DDB tables.

// Pinpoint Parameters
const PHONE_VERIFICATION_CALL_TIMEOUT = 1000; // Timeout on call to Pinpoint phone verification endpoint

// Logging level configuration
const LOG_LEVEL = 1; // 1 = INFO, 2 = ERROR, 3 = NOLOG

// Threat levels definitions
const THREAT_SIGNAL_LEVEL = { 'UNACCEPTABLE': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 }; // Threat levels
const THREAT_BLOCK_THRESHOLDS = { 'COUNT': 5, 'UNACCEPTABLE': 4, 'HIGH': 3, 'MEDIUM': 2 } // Thresholds to be used for blocking
const THREAT_ACTIONS = { 'BLOCK': 0, 'PASS': 1 }; // Possible actions upon detecting threats

// Velocity checks parameters
const EVALUATION_WINDOW_DURATION = 86400; // Look at number of requests in the last 24 hours when checking velocity of an IP or phone number
const SUFFIX_LENGTH = 3; // the suffix length, used to derive the phone prefix used in velocity checks

// Filters parameters
const PHONE_COUNTRY_BLACKLIST = ['MH', 'SB']; // e.g. Countries with high SMS cost delivery, where you are not operating at all https://s3.amazonaws.com/aws-messaging-pricing-information/TextMessageOutbound/prices.json 
const PHONE_TYPE_BLACKLIST = ['LANDLINE', 'VOIP', 'INVALID', 'OTHER']; // Only allow MOBILE and PREPAID phone types

// Risk score calculation 
const CORE_COUNTRIES = ['AE', 'SA', 'EG']; // Countries where most of SMS OTPs are supposed to come from, and go to.
const THREAT_WEIGHTS = { 'IP_NON_CORE_COUNTRY': 1.25, 'BOT_SIGNAL': 2, 'ANONYMIZING_IP': 1.5, 'DATACENTER_IP': 1.4, 'PHONE_NON_CORE_COUNTRY': 1.25, 'IP_VELOCITY': 2, 'PHONE_VELOCITY': 2, 'PHONE_PREFIX_VELOCITY': 2, 'SESSION_VELOCITY': 2 };
const VELOCITY_THRESHOLD = { 'PHONE_VELOCITY_THRESHOLD': 5, 'IP_VELOCITY_THRESHOLD': 5, 'PHONE_PREFIX_VELOCITY_THRESHOLD': 10 };
const RISK_REFERENCE = { 'LOW': 1.25, 'MEDIUM': 2 };

// At which level of threat we start blocking in the function
const BLOCK_LEVEL = THREAT_BLOCK_THRESHOLDS.COUNT; // no blocking, just counting for demo purpose

export const handler = async (event) => {
  const request = event.Records[0].cf.request;

  // Get inputs form downstream. TODO better handle errors in this section
  const rid = event.Records[0].cf.config.requestId;
  const ip = request.clientIp;
  const body = Buffer.from(request.body.data, 'base64').toString();
  const params = JSON.parse(body);
  const phone = params.phone;

  // initializing the requestSignals that contains all info about the SMS generation attempt
  const requestSignals = { threats: [] };

  if (request.headers['cloudfront-viewer-country']) requestSignals.ip_country = request.headers['cloudfront-viewer-country'][0].value; // info sent by CloudFront
  if (request.headers['x-amzn-waf-vpn-signal']) requestSignals.anonymizing_ip = true; // info sent by AWS WAF
  if (request.headers['x-amzn-waf-datacenter-signal']) requestSignals.dc_ip = true; // info sent by AWS WAF
  if (request.headers['x-amzn-waf-bot-signal']) requestSignals.bot_signal = true; // info sent by AWS WAF
  if (request.headers['x-amzn-waf-session-velocity']) { // info sent by AWS WAF. TODO make the threshold configurable
    if (request.headers['x-amzn-waf-session-velocity'][0].value === 'low') {
      requestSignals.session_velocity = 1; 
    } else if (request.headers['x-amzn-waf-session-velocity'][0].value === 'medium') {
      requestSignals.session_velocity = 2;

    } else if (request.headers['x-amzn-waf-session-velocity'][0].value === 'high') {
      requestSignals.session_velocity = 3;
    }
  }

  logInfo(`Received request with ip=${ip}, phone${phone}, and request-id=${rid}`);

  // Filter based on information about the destination phone number using PinPoint API. 
  const validatePhoneNumberWrapper = () => validatePhoneNumber(phone);
  const phoneVerification = await safeCall(validatePhoneNumberWrapper, PHONE_VERIFICATION_CALL_TIMEOUT);   // Wrap the call with a function to handle error and timeout 
  if (phoneVerification) {
    requestSignals.phone_country = phoneVerification.phoneCountry;
    requestSignals.phone_type = phoneVerification.phoneType;
    logInfo(`Phone info: country=${requestSignals.phone_country}, type = ${requestSignals.phone_type}`);
    // First filter based on the country of the destination phone number
    if (PHONE_COUNTRY_BLACKLIST.includes(requestSignals.phone_country)) {
      logInfo(`BANNED_PHONE_COUNTRY signal: phone country is coming from banned country ${requestSignals.phone_country}`);
      requestSignals.threats.push('BANNED_PHONE_COUNTRY');
      if (actionOnThreat(THREAT_SIGNAL_LEVEL.UNACCEPTABLE) == THREAT_ACTIONS.BLOCK) return sendBlock('BANNED_PHONE_COUNTRY');
    }
    // Second filter based on the phone type
    if (PHONE_TYPE_BLACKLIST.includes(requestSignals.phone_type)) {
      logInfo(`BANNED_PHONE_TYPE signal: phone type ${requestSignals.phone_type} is not supported`);
      requestSignals.threats.push('BANNED_PHONE_TYPE');
      if (actionOnThreat(THREAT_SIGNAL_LEVEL.UNACCEPTABLE) == THREAT_ACTIONS.BLOCK) return sendBlock('BANNED_PHONE_TYPE');
    }
  } else {
    logError('Could not apply logic related to phone verification')
  }

  // Apply velocity checks by calling DynamoDB
  const { ipCount, phonePrefixCount, phoneCount } = await velocityCheck(rid, ip, phone);
  requestSignals.ipCount = ipCount;
  requestSignals.phonePrefixCount = phonePrefixCount;
  requestSignals.phoneCount = phoneCount;

  // Calculate risk score
  const risk = getRiskScore(requestSignals);

  if (actionOnThreat(getThreatLevel(risk.score)) == THREAT_ACTIONS.BLOCK) return sendBlock();
  requestSignals.threats.push(risk.elements);

  const threatSignals = requestSignals.threats.join(';');
  logInfo(`Threats observed: ${threatSignals}`);

  request.headers['x-sms-threat'] = [{ value: threatSignals}]; 

  return request;
};

function getThreatLevel(score){
  if (score < RISK_REFERENCE.LOW) {
    return THREAT_SIGNAL_LEVEL.LOW;
  } else if (score < RISK_REFERENCE.MEDIUM) {
    return THREAT_SIGNAL_LEVEL.MEDIUM;
  }

  return THREAT_SIGNAL_LEVEL.HIGH;
}

function getRiskScore(requestSignals) {
  var score = 1;
  const riskElements = [];

  if (!CORE_COUNTRIES.includes(requestSignals.ip_country)) {
    score = score * THREAT_WEIGHTS.IP_NON_CORE_COUNTRY;
    riskElements.push("IP_NON_CORE_COUNTRY");
  }
  if (!CORE_COUNTRIES.includes(requestSignals.phone_country)) {
    score = score * THREAT_WEIGHTS.PHONE_NON_CORE_COUNTRY;
    riskElements.push("PHONE_NON_CORE_COUNTRY");
  }
  if (requestSignals.bot_signal) {
    score = score * THREAT_WEIGHTS.BOT_SIGNAL;
    riskElements.push("BOT_SIGNAL");
  }
  if (requestSignals.anonymizing_ip) {
    score = score * THREAT_WEIGHTS.ANONYMIZING_IP;
    riskElements.push("ANONYMIZING_IP");
  }
  if (requestSignals.dc_ip) {
    score = score * THREAT_WEIGHTS.DATACENTER_IP;
    riskElements.push("DATACENTER_IP");
  }
  if ((typeof requestSignals.ipCount !== 'undefined') && (requestSignals.ipCount > VELOCITY_THRESHOLD.IP_VELOCITY_THRESHOLD)) {
    score = score * requestSignals.ipCount / VELOCITY_THRESHOLD.IP_VELOCITY_THRESHOLD * THREAT_WEIGHTS.IP_VELOCITY;
    riskElements.push("IP_VELOCITY");
  }
  if ((typeof requestSignals.phoneCount !== 'undefined') && (requestSignals.phoneCount > VELOCITY_THRESHOLD.PHONE_VELOCITY_THRESHOLD)) {
    score = score * requestSignals.phoneCount / VELOCITY_THRESHOLD.PHONE_VELOCITY_THRESHOLD * THREAT_WEIGHTS.PHONE_VELOCITY;
    riskElements.push("PHONE_VELOCITY");
  }
  if ((typeof requestSignals.phonePrefixCount !== 'undefined') && (requestSignals.phonePrefixCount > VELOCITY_THRESHOLD.PHONE_PREFIX_VELOCITY_THRESHOLD)) {
    score = score * requestSignals.phonePrefixCount / VELOCITY_THRESHOLD.PHONE_PREFIX_VELOCITY_THRESHOLD * THREAT_WEIGHTS.PHONE_PREFIX_VELOCITY;
    riskElements.push("PHONE_PREFIX_VELOCITY");
  }
  if (requestSignals.session_velocity) {
    score = score * requestSignals.session_velocity * THREAT_WEIGHTS.SESSION_VELOCITY;
    riskElements.push("SESSION_VELOCITY");
  }

  logInfo(`Calculated score = ${score}`);

  riskElements.push(`score=${score}`);

  const elements = riskElements.join('-');

  return {score, elements};
}

function actionOnThreat(threatLevel) {
  if (threatLevel >= BLOCK_LEVEL) return THREAT_ACTIONS.BLOCK;
  return THREAT_ACTIONS.PASS;
}

async function validatePhoneNumber(phone) {
  const phoneValidationCommand = new PhoneNumberValidateCommand({
    NumberValidateRequest: {
      PhoneNumber: phone,
    },
  });

  const phoneValidation = await ppClient.send(phoneValidationCommand);
  const phoneCountry = phoneValidation.NumberValidateResponse.CountryCodeIso2;
  const phoneType = phoneValidation.NumberValidateResponse.PhoneType;

  return { phoneCountry, phoneType };
}

async function velocityCheck(rid, ip, phone, phoneprefix) {
  const expire_at = Math.floor((new Date().getTime() + DDB_ITEM_TTL * 1000) / 1000); // calculate DDB item expriy time from now
  const t = expire_at - EVALUATION_WINDOW_DURATION; // calculate point in time in wihch the evaluation window starts

  var phoneprefix = phone.slice(0, -SUFFIX_LENGTH); // derive phone prefix on which we are doing velocity checks
  logInfo(`Computed phone prefix by removing last ${SUFFIX_LENGTH} digits: ${phoneprefix}`);

  // more fields can be put in it for further analysis, such as country, risk, etc..
  const putCommand = new BatchWriteCommand({
    RequestItems: {
      [IP_DDB_TABLE_NAME]: [
        {
          PutRequest: {
            Item: {
              'ip': ip,
              'rid': rid,
              'expireAt': expire_at.toString(),
            },
          },
        }
      ],
      [PHONE_DDB_TABLE_NAME]: [
        {
          PutRequest: {
            Item: {
              'phoneprefix': phoneprefix,
              'rid': rid,
              'phone': phone,
              'expireAt': expire_at.toString(),
            },
          },
        }
      ],
    }
  });

  const ipCommand = new QueryCommand(
    {
      TableName: IP_DDB_TABLE_NAME,
      KeyConditionExpression: 'ip = :ip',
      FilterExpression: 'expireAt > :t',
      ExpressionAttributeValues: {
        ':ip': { 'S': ip },
        ':t': { 'S': t.toString() },
      }
    });

  const phoneCommand = new QueryCommand(
    {
      TableName: PHONE_DDB_TABLE_NAME,
      KeyConditionExpression: 'phoneprefix = :phoneprefix',
      FilterExpression: 'phone = :phone and expireAt > :t',
      ExpressionAttributeValues: {
        ':phoneprefix': { 'S': phoneprefix },
        ':phone': { 'S': phone },
        ':t': { 'S': t.toString() },
      }
    });


  const ddbGetRequestVelocityByPhone = () => ddbClient.send(phoneCommand);
  const ddbGetRequestVelocityByPhoneWrapper = safeCall(ddbGetRequestVelocityByPhone, DDB_CALL_TIMEOUT);
  const ddbGetRequestVelocityByIP = () => ddbClient.send(ipCommand);
  const ddbGetRequestVelocityByIPWrapper = safeCall(ddbGetRequestVelocityByIP, DDB_CALL_TIMEOUT);
  const ddbAccountForNewRequest = () => ddbClient.send(putCommand);
  const ddbAccountForNewRequestWrapper = safeCall(ddbAccountForNewRequest, DDB_CALL_TIMEOUT);

  // Wait for all requests to DDB to complete. We are sending read and write in the same time to reduce latency. We accept evnetual consistency.
  return await Promise.all([ddbGetRequestVelocityByIPWrapper, ddbGetRequestVelocityByPhoneWrapper, ddbAccountForNewRequestWrapper]).then((values) => {
    var ipCount, phonePrefixCount, phoneCount;
    if (values[0]) ipCount = values[0].Count;
    if (values[1]) {
      phonePrefixCount = values[1].ScannedCount;
      phoneCount = values[1].Count;
    }
    logInfo(`ipCount=${ipCount}, phonePrefixCount=${phonePrefixCount}, phoneCount=${phoneCount}`);
    return { ipCount, phonePrefixCount, phoneCount };
  });
}

function logInfo(message) {
  log(1, message);
}

function logError(message) {
  log(2, message);
}

function log(level, message) {
  if ((level == 1) && level >= LOG_LEVEL) console.log(message);
  if ((level == 2) && level >= LOG_LEVEL) console.error(message);
}

// TODO allow it to send fake info
function sendBlock(message) {
  logInfo('Blocking request');
  return {
    status: 403,
    headers: {
      'content-type': [{
        value: 'application/json',
      }],
    },
    body: `{"response": "${message?message:'sms fraud'}"}`,
  };
}

async function safeCall(asyncFn, timeoutMs) {
  let timeoutHandle;

  // handles timeout
  const timeoutPromise = new Promise((resolve, reject) => {
    timeoutHandle = setTimeout(() => {
      resolve();
      logError(`Async function ${asyncFn.name} timed out`);
    }, timeoutMs);
  });

  // manage error gracefully
  const asyncFnWrapper = () => asyncFn().catch(function (error) {
    logError(`Error in ${asyncFn.name}: ${error}`);
  });

  return Promise.race([asyncFnWrapper(), timeoutPromise]).finally(() => {
    clearTimeout(timeoutHandle);
  });
}


