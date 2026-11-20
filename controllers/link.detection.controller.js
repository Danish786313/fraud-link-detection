const Joi = require('joi');
require("dotenv").config();
const runLocalHeuristics = require('../services/scanlink');

const urlSchema = Joi.object({
  link: Joi.string().uri().message({
    'string.empty': 'link is required',
    'string.uri': 'link must be valid uri',
    'string.base': 'link must e valid uri',
    'any.required': 'link is required'
  })
});

exports.custumFraudDetectionCont = async (req, res) => {
  try {
    const { error, value } = urlSchema.validateAsync(req.body);
    if (error && error.details[0].message) {
      return res.send({
        error: error.details[0].message
      });
    }

    return res.send(await runLocalHeuristics(req.body.link));

  } catch (err) {
    console.log(":::  err  :::", err);
    return res.send({
      error: err.message
    });
  }
};
