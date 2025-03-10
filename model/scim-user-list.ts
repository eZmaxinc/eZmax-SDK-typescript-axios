/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { ScimUser } from './scim-user';

/**
 * 
 * @export
 * @interface ScimUserList
 */
export interface ScimUserList {
    /**
     * 
     * @type {number}
     * @memberof ScimUserList
     */
    /*'totalResults'?: number;*/
    'totalResults'?: number;
    /**
     * 
     * @type {number}
     * @memberof ScimUserList
     */
    /*'itemsPerPage'?: number;*/
    'itemsPerPage'?: number;
    /**
     * 
     * @type {number}
     * @memberof ScimUserList
     */
    /*'startIndex'?: number;*/
    'startIndex'?: number;
    /**
     * 
     * @type {Array<string>}
     * @memberof ScimUserList
     */
    /*'schemas'?: Array<string>;*/
    'schemas'?: Array<string>;
    /**
     * 
     * @type {Array<ScimUser>}
     * @memberof ScimUserList
     */
    /*'Resources'?: Array<ScimUser>;*/
    'Resources'?: Array<ScimUser>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimUserList Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimUserList
 */
export class DataObjectScimUserList {
   totalResults?:number = undefined
   itemsPerPage?:number = undefined
   startIndex?:number = undefined
   schemas?:Array<string> = undefined
   Resources?:Array<ScimUser> = undefined
}

/**
 * @export 
 * A ScimUserList Validation Object
 * @class ValidationObjectScimUserList
 */
export class ValidationObjectScimUserList {
   totalResults = {
      type: 'integer',
      required: false
   }
   itemsPerPage = {
      type: 'integer',
      required: false
   }
   startIndex = {
      type: 'integer',
      required: false
   }
   schemas = {
      type: 'array',
      required: false
   }
   Resources = {
      type: 'array',
      required: false
   }
} 


