const express = require('express');
const router = express.Router();
const linkDetectionController = require('../controllers/linkDetectionController');

// Detection endpoints (both /detect and /detect-v2 supported)
router.post('/detect', linkDetectionController.customFraudDetectionController);

module.exports = router;
