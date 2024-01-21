/**
 * BlogRoutes.js
 * @description :: CRUD API routes for Blog
 */

const express = require('express');
const router = express.Router();
const BlogController = require('../../controller/admin/BlogController');
const { PLATFORM } =  require('../../constants/authConstant'); 
const auth = require('../../middleware/auth');
const checkRolePermission = require('../../middleware/checkRolePermission');
router.route('/admin/blog/create').post(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.addBlog);
router.route('/admin/blog/list').post(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.findAllBlog);
router.route('/admin/blog/count').post(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.getBlogCount);
router.route('/admin/blog/:id').get(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.getBlog);
router.route('/admin/blog/update/:id').put(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.updateBlog);    
router.route('/admin/blog/partial-update/:id').put(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.partialUpdateBlog);
router.route('/admin/blog/softDelete/:id').put(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.softDeleteBlog);
router.route('/admin/blog/softDeleteMany').put(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.softDeleteManyBlog);
router.route('/admin/blog/addBulk').post(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.bulkInsertBlog);
router.route('/admin/blog/updateBulk').put(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.bulkUpdateBlog);
router.route('/admin/blog/delete/:id').delete(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.deleteBlog);
router.route('/admin/blog/deleteMany').post(auth(PLATFORM.ADMIN),checkRolePermission,BlogController.deleteManyBlog);

module.exports = router;
