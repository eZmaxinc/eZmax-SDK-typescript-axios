/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The name of the Usergroup
 * @export
 * @interface MultilingualUsergroupName
 */
export interface MultilingualUsergroupName {
    /**
     * The name of the Usergroup in French
     * @type {string}
     * @memberof MultilingualUsergroupName
     */
    'sUsergroupName1'?: string;
    /**
     * The name of the Usergroup in English
     * @type {string}
     * @memberof MultilingualUsergroupName
     */
    'sUsergroupName2'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A MultilingualUsergroupName Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectMultilingualUsergroupName
 */
export class DataObjectMultilingualUsergroupName {
   sUsergroupName1?:string = undefined
   sUsergroupName2?:string = undefined
}

/**
 * @export 
 * A MultilingualUsergroupName Validation Object
 * @class ValidationObjectMultilingualUsergroupName
 */
export class ValidationObjectMultilingualUsergroupName {
   sUsergroupName1 = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: false
   }
   sUsergroupName2 = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: false
   }
} 


