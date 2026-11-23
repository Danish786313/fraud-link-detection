const express = require('express');
const router = express.Router();
const linkDetectionController = require('../controllers/linkDetectionController');

router.post('/detect', linkDetectionController.customFraudDetectionController);

module.exports = router;
