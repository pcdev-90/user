/**
 * BlogRoutes.js
 * @description :: CRUD API routes for Blog
 */

const express = require('express');
const router = express.Router();
const BlogController = require('../../../controller/device/v1/BlogController');
const { PLATFORM } =  require('../../../constants/authConstant'); 
const auth = require('../../../middleware/auth');
const checkRolePermission = require('../../../middleware/checkRolePermission');
router.route('/device/api/v1/blog/create').post(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.addBlog);
router.route('/device/api/v1/blog/list').post(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.findAllBlog);
router.route('/device/api/v1/blog/count').post(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.getBlogCount);
router.route('/device/api/v1/blog/:id').get(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.getBlog);
router.route('/device/api/v1/blog/update/:id').put(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.updateBlog);    
router.route('/device/api/v1/blog/partial-update/:id').put(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.partialUpdateBlog);
router.route('/device/api/v1/blog/softDelete/:id').put(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.softDeleteBlog);
router.route('/device/api/v1/blog/softDeleteMany').put(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.softDeleteManyBlog);
router.route('/device/api/v1/blog/addBulk').post(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.bulkInsertBlog);
router.route('/device/api/v1/blog/updateBulk').put(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.bulkUpdateBlog);
router.route('/device/api/v1/blog/delete/:id').delete(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.deleteBlog);
router.route('/device/api/v1/blog/deleteMany').post(auth(PLATFORM.DEVICE),checkRolePermission,BlogController.deleteManyBlog);

module.exports = router;
