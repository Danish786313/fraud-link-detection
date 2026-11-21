const sendSuccess = (res, data = null, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json({
    success: true,
    message,
    data
  });
};

const sendError = (res, message = 'Something went wrong', statusCode = 500, error = null) => {
  const payload = {
    success: false,
    message
  };

  if (error !== null) {
    payload.error = error;
  }

  return res.status(statusCode).json(payload);
};

module.exports = {
  sendSuccess,
  sendError
};
