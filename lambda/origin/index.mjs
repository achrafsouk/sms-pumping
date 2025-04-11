export const handler = async (event) => {
  console.log(event);
  var response = {
    'sms-risk' : event.headers['sms-risk']
  };

  
  return {
    statusCode: 200,
    headers: { "content-type": "application/json" },
    body:  JSON.stringify(response),
  };
};
