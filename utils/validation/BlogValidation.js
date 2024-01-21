/**
 * BlogValidation.js
 * @description :: validate each post and put request as per Blog model
 */

const joi = require('joi');
const {
  options, isCountOnly, include, select 
} = require('./commonFilterValidation');

/** validation keys and properties of Blog */
exports.schemaKeys = joi.object({
  title: joi.string().allow(null).allow(''),
  alternativeHeadline: joi.string().allow(null).allow(''),
  image: joi.string().allow(null).allow(''),
  publishDate: joi.string().allow(null).allow(''),
  authorName: joi.string().allow(null).allow(''),
  authorImage: joi.string().allow(null).allow(''),
  authorEmail: joi.string().allow(null).allow(''),
  publisherName: joi.string().allow(null).allow(''),
  publisherUrl: joi.string().allow(null).allow(''),
  publisherLogo: joi.string().allow(null).allow(''),
  keywords: joi.string().allow(null).allow(''),
  articleSection: joi.string().allow(null).allow(''),
  articleBody: joi.string().allow(null).allow(''),
  description: joi.string().allow(null).allow(''),
  slug: joi.string().allow(null).allow(''),
  url: joi.string().allow(null).allow(''),
  isDraft: joi.boolean(),
  isDeleted: joi.boolean(),
  isActive: joi.boolean()
}).unknown(true);

/** validation keys and properties of Blog for updation */
exports.updateSchemaKeys = joi.object({
  title: joi.string().allow(null).allow(''),
  alternativeHeadline: joi.string().allow(null).allow(''),
  image: joi.string().allow(null).allow(''),
  publishDate: joi.string().allow(null).allow(''),
  authorName: joi.string().allow(null).allow(''),
  authorImage: joi.string().allow(null).allow(''),
  authorEmail: joi.string().allow(null).allow(''),
  publisherName: joi.string().allow(null).allow(''),
  publisherUrl: joi.string().allow(null).allow(''),
  publisherLogo: joi.string().allow(null).allow(''),
  keywords: joi.string().allow(null).allow(''),
  articleSection: joi.string().allow(null).allow(''),
  articleBody: joi.string().allow(null).allow(''),
  description: joi.string().allow(null).allow(''),
  slug: joi.string().allow(null).allow(''),
  url: joi.string().allow(null).allow(''),
  isDraft: joi.boolean(),
  isDeleted: joi.boolean(),
  isActive: joi.boolean(),
  id: joi.number().integer()
}).unknown(true);

let keys = ['query', 'where'];
/** validation keys and properties of Blog for filter documents from collection */
exports.findFilterKeys = joi.object({
  options: options,
  ...Object.fromEntries(
    keys.map(key => [key, joi.object({
      title: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      alternativeHeadline: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      image: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      publishDate: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      authorName: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      authorImage: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      authorEmail: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      publisherName: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      publisherUrl: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      publisherLogo: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      keywords: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      articleSection: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      articleBody: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      description: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      slug: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      url: joi.alternatives().try(joi.array().items(),joi.string(),joi.object()),
      isDraft: joi.alternatives().try(joi.array().items(),joi.boolean(),joi.object()),
      isDeleted: joi.alternatives().try(joi.array().items(),joi.boolean(),joi.object()),
      isActive: joi.alternatives().try(joi.array().items(),joi.boolean(),joi.object()),
      id: joi.any()
    }).unknown(true),])
  ),
  isCountOnly: isCountOnly,
  include: joi.array().items(include),
  select: select
    
}).unknown(true);
