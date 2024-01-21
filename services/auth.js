/**
 * auth.js
 * @description :: service functions used in authentication
 */

const model = require('../model/index');
const dbService = require('../utils/dbService');
const {
  JWT,LOGIN_ACCESS,
  PLATFORM,MAX_LOGIN_RETRY_LIMIT,LOGIN_REACTIVE_TIME,DEFAULT_SEND_LOGIN_OTP,SEND_LOGIN_OTP,FORGOT_PASSWORD_WITH
} = require('../constants/authConstant');
const jwt = require('jsonwebtoken');
const common = require('../utils/common');
const dayjs = require('dayjs');
const bcrypt = require('bcrypt');
const emailService = require('./email');
const smsService = require('./sms');
const ejs = require('ejs');
const uuid = require('uuid').v4;

/**
 * @description : service to generate JWT token for authentication.
 * @param {obj} user : user who wants to login.
 * @param {string} secret : secret for JWT.
 * @return {string}  : returns JWT token.
 */
const generateToken = async (user,secret) => {
  return jwt.sign( {
    id:user.id,
    'username':user.username
  }, secret, { expiresIn: JWT.EXPIRES_IN * 60 });
};

/**
 * @description : service to send email containing OTP.
 * @param {obj} user : user document.
 * @return {boolean} : returns true if succeed otherwise false.
 */
const sendEmailForLoginOtp = async (user) => {
  try {
    const where = { 
      id:user.id,
      isActive: true,
      isDeleted: false,        
    };
    let otp = common.randomNumber();
    let expires = dayjs();
    expires = expires.add(6, 'hour').toISOString();
    await dbService.update(model.userAuthSettings, { userId:user.id }, {
      loginOTP: otp,
      expiredTimeOfLoginOTP: expires
    });
    
    let mailObj = {
      subject: 'Login OTP',
      to: user.email,
      template: '/views/email/SendOTP',
      data: { otp: otp }
    };
    await emailService.sendMail(mailObj);
    return true;
  } catch (error) {
    return false;
  }
};

/**
 * @description : service of login user.
 * @param {string} username : username of user.
 * @param {string} password : password of user.
 * @param {string} platform : platform.
 * @param {boolean} roleAccess: a flag to request user`s role access
 * @return {obj} : returns authentication status. {flag, data}
 */
const loginUser = async (username,password,platform,roleAccess) => {
  try {
    let where = { $or:[{ username:username },{ email:username }] };
    where.isActive = true;where.isDeleted = false;            const user = await dbService.findOne(model.user,where);
    if (!user) {
      return {
        flag:true,
        data:'User not exists'
      };
    } 
    let userAuth = await dbService.findOne(model.userAuthSettings, { userId: user.id });
    if (userAuth && userAuth.loginRetryLimit >= MAX_LOGIN_RETRY_LIMIT) {
      let now = dayjs();
      if (userAuth.loginReactiveTime) {
        let limitTime = dayjs(userAuth.loginReactiveTime);
        if (limitTime > now) {
          let expireTime = dayjs().add(LOGIN_REACTIVE_TIME, 'minute');
          if (!(limitTime > expireTime)){
            return {
              flag:true,
              data:`you have exceed the number of limit.you can login after ${common.getDifferenceOfTwoDatesInTime(now,limitTime)}.`
            }; 
          }  
          await dbService.update(model.userAuthSettings, { userId:user.id }, {
            loginReactiveTime: expireTime.toISOString(),
            loginRetryLimit: userAuth.loginRetryLimit + 1
          });
          return {
            flag: true,
            data:`you have exceed the number of limit.you can login after ${common.getDifferenceOfTwoDatesInTime(now,expireTime)}.`
          };
        } else {
          await dbService.update(model.userAuthSettings, { userId:user.id }, {
            loginReactiveTime: null,
            loginRetryLimit: 0
          });
          userAuth = await dbService.findOne(model.userAuthSettings, { userId: user.id });
        }
      } else {
        // send error
        let expireTime = dayjs().add(LOGIN_REACTIVE_TIME, 'minute');
        await dbService.update(model.userAuthSettings, { userId:user.id }, {
          loginReactiveTime: expireTime.toISOString(),
          loginRetryLimit: userAuth.loginRetryLimit + 1
        });
        return {
          flag: true,
          data:`you have exceed the number of limit.you can login after ${common.getDifferenceOfTwoDatesInTime(now,expireTime)}.`
        };
      }
    }
    if (password){
      let isPasswordMatched  = await user.isPasswordMatch(password);
      if (!isPasswordMatched){
        await dbService.update(model.userAuthSettings,{ userId:user.id },{ loginRetryLimit:userAuth.loginRetryLimit + 1 });
        return {
          flag:true,
          data:'Incorrect Password'
        };
      }
    }
    const userData = user.toJSON();
    let token;
    if (!user.userType){
      return {
        flag:true,
        data:'You have not been assigned any role'
      };
    }
    if (platform == PLATFORM.DEVICE){
      if (!LOGIN_ACCESS[user.userType].includes(PLATFORM.DEVICE)){
        return {
          flag:true,
          data:'you are unable to access this platform'
        };
      }
      token = await generateToken(userData,JWT.DEVICE_SECRET);
    }
    else if (platform == PLATFORM.ADMIN){
      if (!LOGIN_ACCESS[user.userType].includes(PLATFORM.ADMIN)){
        return {
          flag:true,
          data:'you are unable to access this platform'
        };
      }
      token = await generateToken(userData,JWT.ADMIN_SECRET);
    }
    if (userAuth && userAuth.loginRetryLimit){
      await dbService.update(model.userAuthSettings, { userId:user.id }, {
        loginRetryLimit: 0,
        loginReactiveTime: null
      });
    }
    let expire = dayjs().add(JWT.EXPIRES_IN, 'second').toISOString();
    await dbService.createOne(model.userTokens, {
      userId: user.id,
      token: token,
      tokenExpiredTime: expire 
    });
    let userToReturn = {
      ...userData,
      token 
    };
    if (roleAccess){
      userToReturn.roleAccess = await common.getRoleAccessData(model,user.id);
    }
    return {
      flag:false,
      data:userToReturn
    };
                    
  } catch (error) {
    throw new Error(error.message);
  }
};
/**
 * @description : service to change password.
 * @param {obj} params : object of new password, old password and user`s id.
 * @return {obj}  : returns status of change password. {flag,data}
 */
const changePassword = async (params)=>{
  try {
    let password = params.newPassword;
    let oldPassword = params.oldPassword;
    let where = { id:params.userId };
    where.isActive = true;where.isDeleted = false;        let user = await dbService.findOne(model.user,where);
    if (!user || !user.id) {
      return {
        flag:true,
        data:'User not found'
      };
    }
    const isPasswordMatched = await user.isPasswordMatch(oldPassword);
    if (!isPasswordMatched){
      return {
        flag:true,
        data:'Incorrect Old Password'
      };
    }
    password = await bcrypt.hash(password, 8);
    let updatedUser = dbService.update(model.user,where,{ password:password });
    if (!updatedUser) {
      return {
        flag:true,
        data:'password can not changed due to some error.please try again'
      };
    }
    return {
      flag:false,
      data:'Password changed successfully'
    };                
  } catch (error) {
    throw new Error(error.message);
  }
};
/**
 * @description : service to send notification on reset password.
 * @param {obj} user : user document
 * @return {}  : returns status where notification is sent or not
 */
const sendResetPasswordNotification = async (user) => {
  let resultOfEmail = false;
  let resultOfSMS = false;
  try {
    const where = {
      id: user.id,
      isActive: true,
      isDeleted: false,        
    };
    let token = uuid();
    let expires = dayjs();
    expires = expires.add(FORGOT_PASSWORD_WITH.EXPIRE_TIME, 'minute').toISOString();
    await dbService.update(model.userAuthSettings, { userId:user.id },
      {
        resetPasswordCode: token,
        expiredTimeOfResetPasswordCode: expires
      });
    if (FORGOT_PASSWORD_WITH.LINK.email){
      let updatedUser = await dbService.findOne(model.user, where);
      let mailObj = {
        subject: 'Reset Password',
        to: user.email,
        template: '/views/email/ResetPassword',
        data:{ userName:updatedUser.username, }
      };
      try {
        await emailService.sendMail(mailObj);
        resultOfEmail = true;
      } catch (error){
        throw new Error(error.message);
      }
    }
    if (FORGOT_PASSWORD_WITH.LINK.sms){
      let viewType = '/reset-password/';
      let link = `http://localhost:${process.env.PORT}${viewType + token}`;
      const msg = await ejs.renderFile(`${__basedir}/views/sms/ResetPassword/html.ejs`, { link : link });
      let smsObj = {
        to:user.mobileNo,
        message:msg
      };
      try {
        await smsService.sendSMS(smsObj);
        resultOfSMS = true;
      } catch (error){
        throw new Error(error.message);
      }
    }
    return {
      resultOfEmail,
      resultOfSMS
    };
  } catch (error) {
    throw new Error(error.message);
  }
};
/**
 * @description : service to reset password.
 * @param {obj} userId : user`s id 
 * @param {string} newPassword : new password to be set.
 * @return {}  : returns status whether new password is set or not. {flag, data}
 */
const resetPassword = async (userId, newPassword) => {
  try {
    let where = { id: userId };
    where.isActive = true;where.isDeleted = false;        const dbUser = await dbService.findOne(model.user,where);
    if (!dbUser) {
      return {
        flag: true,
        data: 'User not found',
      };
    }
    newPassword = await bcrypt.hash(newPassword, 8);
    let updatedUser = await dbService.update(model.user, where, { password: newPassword });
    if (!updatedUser) {
      return {
        flag: true,
        data: 'Password is not reset successfully',
      };
    }
    await dbService.update(model.userAuthSettings, { userId:userId }, {
      resetPasswordCode: '',
      expiredTimeOfResetPasswordCode: null,
      loginRetryLimit: 0 
    });
    let mailObj = {
      subject: 'Reset Password',
      to: dbUser.email,
      template: '/views/email/SuccessfulPasswordReset',
      data: {
        isWidth: true,
        email: dbUser.email || '-',
        message: 'Your password has been changed Successfully.'
      }
    };
    await emailService.sendMail(mailObj);
    return {
      flag: false,
      data: 'Password reset successfully',
    };
  } catch (error) {
    throw new Error(error.message);
  }
};
/**
 * @description : service to send password via SMS.
 * @param {string} user : user document.
 * @return {boolean}  : returns status whether SMS is sent or not.
 */
const sendPasswordBySMS = async (user) => {
  try {
    const msg = await ejs.renderFile(`${__basedir}/views/sms/InitialPassword/html.ejs`, { password: user.password });
    let smsObj = {
      to: user.mobileNo,
      message: msg
    };
    await smsService.sendSMS(smsObj);
    return true;
  } catch (error) {
    return false;
  }
};
/**
 * @description : service to send password via Email.
 * @param {string} user : user document.
 * @return {boolean}  : returns status whether Email is sent or not.
 */
const sendPasswordByEmail = async (user) => {
  try {
    let msg = `Your Password for login : ${user.password}`;
    let mailObj = {
      subject: 'Your Password!',
      to: user.email,
      template: '/views/email/InitialPassword',
      data: { message:msg }
    };
    try {
      await emailService.sendMail(mailObj);
      return true;
    } catch (error) {
      return false;
    }
  } catch (error) {
    return false;
  }
};

/**
 * @description : service method to send OTP for login.
 * @param {string} username : username of user.
 * @param {string} password : password of user.
 * @return {obj}  : returns status whether OTP is sent or not. {flag, data}
 */
const sendLoginOTP = async (username,password) => {
  try {
    let where = { $or:[{ username:username },{ email:username }] };
    where.isActive = true;where.isDeleted = false;        let user = await dbService.findOne(model.user,where);
    if (!user){
      return {
        flag:true,
        data:'User not found'
      };
    }
    let userAuth = await dbService.findOne(model.userAuthSettings, { userId: user.id });
    if (userAuth && userAuth.loginRetryLimit >= MAX_LOGIN_RETRY_LIMIT) {
      if (userAuth.loginReactiveTime) {
        let now = dayjs();
        let limitTime = dayjs(userAuth.loginReactiveTime);
        if (limitTime > now) {
          let expireTime = dayjs().add(LOGIN_REACTIVE_TIME, 'minute').toISOString();
          await dbService.update(model.userAuthSettings, { userId:user.id }, {
            loginReactiveTime: expireTime,
            loginRetryLimit: userAuth.loginRetryLimit + 1
          });
          return {
            flag: true,
            data: `you have exceed the number of limit.you can login after ${LOGIN_REACTIVE_TIME} minutes.`
          };
        }
      } else {
        let expireTime = dayjs().add(LOGIN_REACTIVE_TIME, 'minute').toISOString();
        await dbService.update(model.userAuthSettings, { userId:user.id }, {
          loginReactiveTime: expireTime,
          loginRetryLimit: userAuth.loginRetryLimit + 1
        });
        return {
          flag: true,
          data: `you have exceed the number of limit.you can login after ${LOGIN_REACTIVE_TIME} minutes.`
        };
      }
    }
    if (password){
      const isPasswordMatched = await user.isPasswordMatch(password);
      if (!isPasswordMatched){
        await dbService.update(model.userAuthSettings, { userId: user.id }, { loginRetryLimit: user.loginRetryLimit + 1 });
        return {
          flag: true,
          data: 'Incorrect password.'
        };
      }
    }
    let res;
    if (DEFAULT_SEND_LOGIN_OTP === SEND_LOGIN_OTP.EMAIL){
      // send Email here
      if (userAuth.loginReactiveTime) {
        await dbService.update(model.userAuthSettings, { userId:user.id }, {
          loginRetryLimit: 0,
          loginReactiveTime: null 
        });
      }    
      res = await sendEmailForLoginOtp(user);
    } else if (DEFAULT_SEND_LOGIN_OTP === SEND_LOGIN_OTP.SMS){
      // send SMS here
    }
    if (!res){
      return {
        flag:true,
        data:'otp can not be sent due to some issue try again later.'
      };    
    }
    return {
      flag:false,
      data:'Please check your email for OTP'
    };
  } catch (error) {
    throw new Error(error.message);
  }
};

/**
 * @description : service to login with OTP.
 * @param {string} username : username of user.
 * @param {string} password : password of user.
 * @param {string} platform : platform.
 * @param {roleAccess} : a flag to request role access of user
 * @return {obj}  : returns authentication object {flag,data}.
 */
const loginWithOTP = async (username, password, platform,roleAccess) => {
  try {
    let result = await loginUser(username, password, platform,roleAccess);
    if (!result.flag) {
      await dbService.update(model.userAuthSettings, { userId:result.data.id }, {
        loginOTP: '',
        expiredTimeOfLoginOTP: null 
      });
    }
    return result;
        
  } catch (error) {
    throw new Error(error.message);
  }
};

module.exports = {
  loginUser,
  changePassword,
  sendResetPasswordNotification,
  resetPassword,
  sendPasswordBySMS,
  sendPasswordByEmail,
  sendLoginOTP,
  loginWithOTP
};