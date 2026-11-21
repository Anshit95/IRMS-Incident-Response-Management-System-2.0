const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../middleware/auth');
const playbookController = require('../controllers/playbookController');

router.use(authenticate);

router.get('/', playbookController.listPlaybooks);
router.get('/:id', playbookController.getPlaybook);
router.post('/:id/run', authorize('admin', 'analyst'), playbookController.executePlaybook);
router.get('/runs/incident/:incidentId', playbookController.getIncidentPlaybookRuns);

module.exports = router;
