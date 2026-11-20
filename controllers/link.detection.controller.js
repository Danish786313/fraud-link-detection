const Joi = require('joi');
require("dotenv").config();
const runLocalHeuristics = require('../services/scanlink');

const urlSchema = Joi.object({
  link: Joi.string().uri().required().messages({
    'string.empty': 'link is required',
    'string.uri': 'link must be valid uri',
    'string.base': 'link must be valid uri',
    'any.required': 'link is required'
  })
});

exports.custumFraudDetectionCont = async (req, res) => {
  try {
    const { error } = urlSchema.validate(req.body);
    if (error && error.details && error.details[0]) {
      return sendError(res, error.details[0].message, 400);
    }

    const data = await runLocalHeuristics(req.body.link);
    return sendSuccess(res, data, 'Scan completed successfully');

  } catch (err) {
    console.error("::: err :::", err);
    return sendError(res, err.message || 'Internal server error', 500);
  }
};
