/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { PermissionResponse } from './permission-response';

/**
 * @type PermissionResponseCompound
 * A Permission Object and children to create a complete structure
 * @export
 */
/** export type PermissionResponseCompound = PermissionResponse; */
export interface PermissionResponseCompound {
    /**
     * The unique ID of the Permission
     * @type {number}
     * @memberof PermissionResponseCompound
     */
    pkiPermissionID:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof PermissionResponseCompound
     */
    fkiUserID?:number 
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof PermissionResponseCompound
     */
    fkiApikeyID?:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof PermissionResponseCompound
     */
    fkiUsergroupID?:number 
    /**
     * The unique ID of the Company
     * @type {number}
     * @memberof PermissionResponseCompound
     */
    fkiCompanyID?:number 
    /**
     * The unique ID of the Modulesection
     * @type {number}
     * @memberof PermissionResponseCompound
     */
    fkiModulesectionID:number 
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof PermissionResponseCompound
     */
    sCompanyNameX?:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PermissionResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPermissionResponseCompound
 */
export class DataObjectPermissionResponseCompound {
    pkiPermissionID:number = 0
    fkiUserID?:number = undefined
    fkiApikeyID?:number = undefined
    fkiUsergroupID?:number = undefined
    fkiCompanyID?:number = undefined
    fkiModulesectionID:number = 0
    sCompanyNameX?:string = undefined
}

/**
 * @export 
 * A PermissionResponseCompound Validation Object
 * @class ValidationObjectPermissionResponseCompound
 */
export class ValidationObjectPermissionResponseCompound {
   pkiPermissionID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiApikeyID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiCompanyID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: false
   }
   fkiModulesectionID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sCompanyNameX = {
      type: 'string',
      required: false
   }
} 


