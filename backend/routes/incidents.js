const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../middleware/auth');
const c = require('../controllers/incidentController');
const ai = require('../controllers/aiController');

// Incident List & Detail (All authenticated roles)
router.get('/', authenticate, c.listIncidents);
router.get('/:id', authenticate, c.getIncident);

// Incident Modifications (Admin and Analyst only)
router.post('/', authenticate, authorize('admin', 'analyst'), c.createIncident);
router.put('/:id', authenticate, authorize('admin', 'analyst'), c.updateIncident);
router.patch('/:id/status', authenticate, authorize('admin', 'analyst'), c.updateStatus);
router.delete('/:id', authenticate, authorize('admin'), c.deleteIncident);

// Notes (All can read; Admin/Analyst can add)
router.get('/:id/notes', authenticate, c.getNotes);
router.post('/:id/notes', authenticate, authorize('admin', 'analyst'), c.addNote);

// Evidence (All can read; Admin/Analyst can add)
router.get('/:id/evidence', authenticate, c.getEvidence);
router.post('/:id/evidence', authenticate, authorize('admin', 'analyst'), c.addEvidence);

// Response Actions (All can read; Admin/Analyst can record)
router.get('/:id/actions', authenticate, c.getActions);
router.post('/:id/actions', authenticate, authorize('admin', 'analyst'), c.addAction);

// Incident Timeline
router.get('/:id/timeline', authenticate, c.getTimeline);

// AI Forensic Analyses
router.get('/:id/ai-analysis', authenticate, ai.getAnalyses);
router.post('/:id/ai-analysis', authenticate, authorize('admin', 'analyst'), ai.analyzeIncident);
router.post('/:id/ai-chat', authenticate, authorize('admin', 'analyst'), ai.chatWithAI);

module.exports = router;
