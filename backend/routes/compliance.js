const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const complianceController = require('../controllers/complianceController');

router.use(authenticate);

router.get('/report', complianceController.getReport);
router.get('/verify-chain', complianceController.verifyChain);
router.get('/export-stix/:incidentId', complianceController.exportStix);
router.get('/audit-logs', complianceController.getAuditLogs);

module.exports = router;
