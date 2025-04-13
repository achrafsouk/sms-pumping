export const handler = async (event) => {
  console.log(event);
  var response = {
    'threats-detected' : event.headers['x-sms-threat']
  };

  
  return {
    statusCode: 200,
    headers: { "content-type": "application/json" },
    body:  JSON.stringify(response),
  };
};
