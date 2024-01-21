/**
 * userController.js
 * @description :: exports action methods for user.
 */

const User = require('../../../model/user');
const userSchemaKey = require('../../../utils/validation/userValidation');
const validation = require('../../../utils/validateRequest');
const dbService = require('../../../utils/dbService');
const auth = require('../../../services/auth');
const models = require('../../../model');
const deleteDependentService = require('../../../utils/deleteDependent');
const utils = require('../../../utils/common');

/**
 * @description : change password
 * @param {Object} req : request including user credentials.
 * @param {Object} res : response contains updated user record.
 * @return {Object} : updated user record {status, message, data}
 */
const changePassword = async (req, res) => {
  try {
    let params = req.body;
    if (!params.newPassword || !params.oldPassword) {
      return res.validationError();
    }
    let result = await auth.changePassword({
      ...params,
      userId:req.user.id
    });
    if (result.flag){
      return res.failure({ message :result.data });
    }
    return res.success({ message :result.data });
  } catch (error) {
    return res.internalServerError({ data:error.message }); 
  }
};
/**
 * @description : update user profile.
 * @param {Object} req : request including user profile details to update in request body.
 * @param {Object} res : updated user record.
 * @return {Object} : updated user record. {status, message, data}
 */
const updateProfile = async (req, res) => {
  try {
    const data = {
      ...req.body,
      id:req.user.id
    };
    let validateRequest = validation.validateParamsWithJoi(
      data,
      userSchemaKey.updateSchemaKeys
    );
    if (!validateRequest.isValid) {
      return res.validationError({ message : `Invalid values in parameters, ${validateRequest.message}` });
    }
    if (data.password) delete data.password;
    if (data.createdAt) delete data.createdAt;
    if (data.updatedAt) delete data.updatedAt;
    if (data.id) delete data.id;
    let result = await dbService.update(User, { id :req.user.id } ,data);
    if (!result){
      return res.recordNotFound();
    }            
    return  res.success({ data :result });
  }
  catch (error){
    return res.internalServerError({ data:error.message }); 
  }
};

/**
 * @description : get information of logged-in User.
 * @param {Object} req : authentication token is required
 * @param {Object} res : Logged-in user information
 * @return {Object} : Logged-in user information {status, message, data}
 */
const getLoggedInUserInfo = async (req, res) => {
  try {
    const query = {
      id: req.user.id,
      isDeleted: false
    };
    query.isActive = true;
    let result = await dbService.findOne(User,query);
    if (!result) {
      return res.recordNotFound();
    }
    return res.success({ data: result });
  } catch (error){
    return res.internalServerError({ data: error.message });
  }
};

module.exports = {
  changePassword,
  updateProfile,
  getLoggedInUserInfo,
};
