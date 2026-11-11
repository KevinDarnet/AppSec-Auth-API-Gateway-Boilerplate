import { Router } from 'express';
import { HealthController } from './health.controller.js';

const router = Router();

router.get('/live', HealthController.live);
router.get('/ready', HealthController.ready);

export const healthRoutes = router;
