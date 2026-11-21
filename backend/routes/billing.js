const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../middleware/auth');
const billingController = require('../controllers/billingController');

router.use(authenticate);

router.get('/subscription', billingController.getSubscription);
router.post('/upgrade', authorize('admin'), billingController.handleUpgrade);

module.exports = router;
