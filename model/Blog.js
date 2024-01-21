/**
 * Blog.js
 * @description :: sequelize model of database table Blog
 */

const { DataTypes } = require('sequelize');
const sequelize = require('../config/dbConnection');
const sequelizePaginate = require('sequelize-paginate');
const sequelizeTransforms = require('sequelize-transforms');
const { convertObjectToEnum } = require('../utils/common');
let Blog = sequelize.define('Blog',{
  id:{
    type:DataTypes.INTEGER,
    primaryKey:true,
    autoIncrement:true
  },
  title:{ type:DataTypes.STRING },
  alternativeHeadline:{ type:DataTypes.STRING },
  image:{ type:DataTypes.STRING },
  publishDate:{ type:DataTypes.STRING },
  authorName:{ type:DataTypes.STRING },
  authorImage:{ type:DataTypes.STRING },
  authorEmail:{ type:DataTypes.STRING },
  publisherName:{ type:DataTypes.STRING },
  publisherUrl:{ type:DataTypes.STRING },
  publisherLogo:{ type:DataTypes.STRING },
  keywords:{ type:DataTypes.STRING },
  articleSection:{ type:DataTypes.STRING },
  articleBody:{ type:DataTypes.STRING },
  description:{ type:DataTypes.STRING },
  slug:{ type:DataTypes.STRING },
  url:{ type:DataTypes.STRING },
  isDraft:{ type:DataTypes.BOOLEAN },
  isDeleted:{ type:DataTypes.BOOLEAN },
  isActive:{ type:DataTypes.BOOLEAN },
  createdAt:{ type:DataTypes.DATE },
  updatedAt:{ type:DataTypes.DATE },
  updatedBy:{ type:DataTypes.INTEGER },
  addedBy:{ type:DataTypes.INTEGER }
}
,{
  hooks:{
    beforeCreate: [
      async function (Blog,options){
        Blog.isActive = true;
        Blog.isDeleted = false;

      },
    ],
    beforeBulkCreate: [
      async function (Blog,options){
        if (Blog !== undefined && Blog.length) { 
          for (let index = 0; index < Blog.length; index++) { 
        
            const element = Blog[index]; 
            element.isActive = true; 
            element.isDeleted = false; 
  
          } 
        }
      },
    ],
  }
  ,indexes:  [{
    'using':'BTREE',
    'fields':[{
      'attribute':'title',
      'order':'ASC',
      'operator':'',
      'length':10,
      'value':''
    }],
    'name':'Blog_index_title_index_1'
  },{
    'using':'BTREE',
    'fields':[{
      'attribute':'publishDate',
      'order':'DESC',
      'operator':'',
      'length':10,
      'value':''
    }],
    'name':'Blog_index_publishdate_index_2'
  }]
}
);
Blog.prototype.toJSON = function () {
  let values = Object.assign({}, this.get());
  return values;
};
sequelizeTransforms(Blog);
sequelizePaginate.paginate(Blog);
module.exports = Blog;
