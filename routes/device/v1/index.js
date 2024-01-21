/**
 * index route file of device platform.
 * @description: exports all routes of device platform.
 */
const express =  require('express');
const router =  express.Router();
router.use('/device/auth',require('./auth'));
router.use(require('./BlogRoutes'));
router.use(require('./userRoutes'));
router.use(require('./uploadRoutes'));

module.exports = router;
