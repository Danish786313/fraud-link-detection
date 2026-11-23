const Joi = require('joi');
require("dotenv").config();
const runLocalHeuristics = require('../services/linkScanner.service');

const urlSchema = Joi.object({
  link: Joi.string().trim().required().messages({
    'string.empty': 'link is required',
    'any.required': 'link is required'
  })
});

const customFraudDetectionController = async (req, res, next) => {
  try {
    const { error } = urlSchema.validate(req.body);
    if (error && error.details && error.details[0]) {
      return sendError(res, error.details[0].message, 400);
    }

    const data = await runLocalHeuristics(req.body.link);
    return sendSuccess(res, data, 'Scan completed successfully');

  } catch (err) {
    console.error("::: Error in custom fraud detection controller :::", err);
    if (typeof next === 'function') {
      return next(err);
    }
    return sendError(res, err.message || 'Internal server error', 500);
  }
};

module.exports = {
  customFraudDetectionController
};
