const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../middleware/auth');
const { getReport, listReports } = require('../controllers/reportController');
const { getAnalytics } = require('../controllers/analyticsController');
const { listUsers, createUser, updateUser, getAnalysts } = require('../controllers/userController');

// Reports (All authenticated roles can read)
router.get('/reports', authenticate, listReports);
router.get('/reports/:id', authenticate, getReport);

// Analytics
router.get('/analytics', authenticate, getAnalytics);

// User Management (Admin Only)
router.get('/users', authenticate, authorize('admin'), listUsers);
router.post('/users', authenticate, authorize('admin'), createUser);
router.patch('/users/:id', authenticate, authorize('admin'), updateUser);

// Active Analysts directory for assignment
router.get('/analysts', authenticate, getAnalysts);

module.exports = router;
