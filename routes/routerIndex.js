const express = require('express')
const router = express.Router()
const linkDetectionCont = require("../controllers/link.detection.controller")


router.post('/detect-v2', linkDetectionCont.custumFraudDetectionCont)


module.exports = router;