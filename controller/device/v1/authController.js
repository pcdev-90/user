/**
 * authController.js
 * @description :: exports authentication methods
 */
const authService =  require('../../../services/auth');
const {
  user,role,userRole,userAuthSettings,userTokens,pushNotification
} = require('../../../model/index');
const dbService = require('../../../utils/dbService');
const dayjs = require('dayjs');
const userSchemaKey = require('../../../utils/validation/userValidation');
const validation = require('../../../utils/validateRequest');
const authConstant = require('../../../constants/authConstant');
const { checkUniqueFieldsInDatabase } = require('../../../utils/common');
const {
  sendPasswordBySMS, sendPasswordByEmail 
} = require('../../../services/auth');
    
/**
 * @description : user registration 
 * @param {Object} req : request for register
 * @param {Object} res : response for register
 * @return {Object} : response for register {status, message, data}
 */
const register = async (req, res) => {
  try {
    let dataToRegister = req.body;
    let validateRequest = validation.validateParamsWithJoi(
      dataToRegister,
      userSchemaKey.schemaKeys
    );
    if (!validateRequest.isValid) {
      return res.validationError({ message : `Invalid values in parameters, ${validateRequest.message}` });
    }
    let isEmptyPassword = false;
    if (!dataToRegister.password){
      isEmptyPassword = true;
      dataToRegister.password = Math.random().toString(36).slice(2);
    } 

    let checkUniqueFields = await checkUniqueFieldsInDatabase(user,[ 'username', 'email' ],dataToRegister,'REGISTER');
    if (checkUniqueFields.isDuplicate){
      return res.validationError({ message : `${checkUniqueFields.value} already exists.Unique ${checkUniqueFields.field} are allowed.` });
    }

    const result = await dbService.createOne(user,{
      ...dataToRegister,
      userType: authConstant.USER_TYPES.User
    });
    if (isEmptyPassword && req.body.email){
      await sendPasswordByEmail({
        email: req.body.email,
        password: req.body.password
      });
    }
    if (isEmptyPassword && req.body.mobileNo){
      await sendPasswordBySMS({
        mobileNo: req.body.mobileNo,
        password: req.body.password
      });
    }
    return  res.success({ data :result });
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }  
};

/**
 * @description : send email or sms to user with OTP on forgot password
 * @param {Object} req : request for forgotPassword
 * @param {Object} res : response for forgotPassword
 * @return {Object} : response for forgotPassword {status, message, data}
 */
const forgotPassword = async (req, res) => {
  const params = req.body;
  try {
    if (!params.email) {
      return res.badRequest({ message : 'Insufficient request parameters! email is required' });
    }
    let where = { email: params.email.toString().toLowerCase() };
    where.isActive = true;where.isDeleted = false;        let found = await dbService.findOne(user,where);
    if (!found) {
      return res.recordNotFound();
    } 
    let {
      resultOfEmail,resultOfSMS
    } = await authService.sendResetPasswordNotification(found);
    if (resultOfEmail && resultOfSMS){
      return res.success({ message :'OTP successfully send.' });
    } else if (resultOfEmail && !resultOfSMS) {
      return res.success({ message :'OTP successfully send to your email.' });
    } else if (!resultOfEmail && resultOfSMS) { 
      return res.success({ message : 'OTP successfully send to your mobile number.' });
    } else {
      return res.failure({ message :'OTP can not be sent due to some issue try again later' });
    }
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }
};

/**
 * @description : validate OTP
 * @param {Object} req : request for validateResetPasswordOtp
 * @param {Object} res : response for validateResetPasswordOtp
 * @return {Object} : response for validateResetPasswordOtp  {status, message, data}
 */ 
const validateResetPasswordOtp = async (req, res) => {
  const params = req.body;
  try {
    if (!params.otp) {
      return res.badRequest({ message : 'Insufficient request parameters! otp is required.' });
    }
    let found = await dbService.findOne(userAuthSettings, { resetPasswordCode: params.otp });
    if (!found || !found.resetPasswordCode) {
      return res.failure({ message :'Invalid OTP' });
    }
    // link expire
    if (dayjs(new Date()).isAfter(dayjs(found.expiredTimeOfResetPasswordCode))) {
      return res.failure({ message :'Your reset password link is expired or invalid' });
    }
    return res.success({ message : 'OTP verified' });
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }
};

/**
 * @description : reset password with code and new password
 * @param {Object} req : request for resetPassword
 * @param {Object} res : response for resetPassword
 * @return {Object} : response for resetPassword {status, message, data}
 */ 
const resetPassword = async (req, res) => {
  const params = req.body;
  try {
    if (!params.code || !params.newPassword) {
      return res.badRequest({ message : 'Insufficient request parameters! code and newPassword is required.' });
    }
    let userAuth = await dbService.findOne(userAuthSettings, { resetPasswordCode: params.code });
    if (userAuth && userAuth.expiredTimeOfResetPasswordCode) {
      if (dayjs(new Date()).isAfter(dayjs(userAuth.expiredTimeOfResetPasswordCode))) {// link expire
        return res.failure({ message :'Your reset password link is expired or invalid' });
      }
    } else {
      // invalid code
      return res.failure({ message :'Invalid Code' });
    }
    let response = await authService.resetPassword(userAuth.userId, params.newPassword);
    if (response.flag){
      return res.failure({ message :response.data });
    }
    return res.success({ message  :response.data });
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }
};

/**
 * @description : send OTP to user for login
 * @param {Object} req : request for sendOtpForLogin
 * @param {Object} res : response for sendOtpForLogin
 * @return {Object} : response for sendOtpForLogin {status, message, data}
 */
const sendOtpForLogin = async (req,res)=>{
  try {
    let params = req.body;
    if (!params.username){
      return res.badRequest({ message : 'Insufficient request parameters! username is required.' });
    }
    let result = await authService.sendLoginOTP(params.username);
    if (result.flag){
      return res.failure({ message :result.data });
    }
    return res.success({ message :result.data });
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }
};

/**
 * @description : login with username and OTP
 * @param {Object} req : request for loginWithOTP
 * @param {Object} res : response for loginWithOTP
 * @return {Object} : response for loginWithOTP {status, message, data}
 */
const loginWithOTP = async (req, res) => {
  const params = req.body;
  try {
    if (!params.code || !params.username) {
      return res.badRequest({ message : 'Insufficient request parameters! username and code is required.' });
    }
    let isCodeVerified = false;
    let where = { $or:[{ username:params.username },{ email:params.username }] };
    where.isActive = true;where.isDeleted = false;        let User = await dbService.findOne(user,where);
    if (!User) {
      // invalid code
      return res.badRequest({ message :'Invalid Code' });
    } 
    let userAuth = await dbService.findOne(userAuthSettings,{ userId:User.id });
    if (userAuth && userAuth.loginOTP && userAuth.expiredTimeOfLoginOTP){
      isCodeVerified = userAuth.loginOTP == params.code ? true : false;
      if (dayjs(new Date()).isAfter(dayjs(userAuth.expiredTimeOfLoginOTP))) {// link expire
        return res.badRequest({ message :'Your reset password link is expired' });
      }
      if (userAuth.loginOTP !== params.code){
        return res.badRequest({ message :'Invalid Code' });
      }
    }
    let roleAccess = false;
    if (req.body.includeRoleAccess){
      roleAccess = req.body.includeRoleAccess;
    }
    let result = await authService.loginWithOTP(params.username, null, authConstant.PLATFORM.DEVICE,roleAccess);
    if (result.flag){
      return res.badRequest({ message :result.data });
    }
    return res.success({
      data:result.data,
      message :'Login successful.'
    });
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }
};
/**
 * @description : send OTP to user for login
 * @param {Object} req : request for sendOtpForLogin
 * @param {Object} res : response for sendOtpForLogin
 * @return {Object} : response for sendOtpForLogin {status, message, data}
 */
const sendOtpForTwoFA = async (req,res)=>{
  try {
    let params = req.body;
    if (!params.username || !params.password){
      return res.badRequest({ message : 'Insufficient request parameters! username and password is required.' });
    }
    let result = await authService.sendLoginOTP(params.username,params.password);
    if (result.flag){
      return res.failure({ message :result.data });
    }
    return res.success({ message :result.data });
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }
};

/**
 * @description : login with OTP
 * @param {Object} req : request for loginWithOTP
 * @param {Object} res : response for loginWithOTP
 * @return {Object} : response for loginWithOTP {status, message, data}
 */
const loginWithTwoFA = async (req, res) => {
  const params = req.body;
  try {
    if (!params.code || !params.username || !params.password) {
      return res.badRequest({ message : 'Insufficient request parameters! username,password and code is required.' });
    }
    let where = { $or:[{ username:params.username },{ email:params.username }] };
    where.isActive = true;where.isDeleted = false;        let User = await dbService.findOne(user,where);
    if (!User) {
      // invalid code
      return res.badRequest({ message :'Invalid Code' });
    } 
    let userAuth = await dbService.findOne(userAuthSettings,{ userId:User.id });
    if (userAuth && userAuth.loginOTP && userAuth.expiredTimeOfLoginOTP){
      if (dayjs(new Date()).isAfter(dayjs(userAuth.expiredTimeOfLoginOTP))) {// link expire
        return res.badRequest({ message :'Your reset password link is expired' });
      }
      if (userAuth.loginOTP !== params.code){
        return res.badRequest({ message :'Invalid Code' });
      }
    }

    let roleAccess = false;
    if (req.body.includeRoleAccess){
      roleAccess = req.body.includeRoleAccess;
    }
    let result = await authService.loginWithOTP(params.username,params.password,authConstant.PLATFORM.DEVICE,roleAccess);
    if (result.flag){
      return res.badRequest({ message :result.data });
    }
    return res.success({
      data:result.data,
      message :'Login successful.'
    });
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }
};

/**
 * @description : logout user
 * @param {Object} req : request for logout
 * @param {Object} res : response for logout
 * @return {Object} : response for logout {status, message, data}
 */
const logout = async (req, res) => {
  try {
    let userToken = await dbService.findOne(userTokens, {
      token: (req.headers.authorization).replace('Bearer ', ''),
      userId:req.user.id 
    });
    userToken.isTokenExpired = true;
    let id = userToken.id;
    delete userToken.id;
    await dbService.update(userTokens,{ id:id }, userToken.toJSON());
    return res.success({ message :'Logged Out Successfully' });
  } catch (error) {
    return res.internalServerError({ message:error.message }); 
  }
};
module.exports = {
  register,
  sendOtpForLogin,
  loginWithOTP,
  sendOtpForTwoFA,
  loginWithTwoFA,
  forgotPassword,
  validateResetPasswordOtp,
  resetPassword,
  logout,
};
