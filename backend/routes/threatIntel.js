const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../middleware/auth');
const threatIntelController = require('../controllers/threatIntelController');

router.use(authenticate);

router.post('/lookup', threatIntelController.lookupIndicator);
router.get('/indicators', threatIntelController.listIndicators);
router.post('/indicators', authorize('admin', 'analyst'), threatIntelController.addIndicator);
router.get('/stats', threatIntelController.getThreatStats);

module.exports = router;
