/**
 * auth.js
 * @description :: express routes of authentication APIs
 */
  
const express =  require('express');
const router  =  express.Router();
const authController =  require('../../../controller/device/v1/authController');
const { PLATFORM } =  require('../../../constants/authConstant'); 
const auth = require('../../../middleware/auth');
router.route('/register').post(authController.register);
router.post('/send_login_otp',authController.sendOtpForLogin);
router.post('/login_with_otp',authController.loginWithOTP);
router.post('/send_otp_2fa',authController.sendOtpForTwoFA);
router.post('/login_with_2fa',authController.loginWithTwoFA);
router.route('/forgot-password').post(authController.forgotPassword);
router.route('/validate-otp').post(authController.validateResetPasswordOtp);
router.route('/reset-password').put(authController.resetPassword);
router.route('/logout').post(auth(PLATFORM.DEVICE), authController.logout);

module.exports = router;
