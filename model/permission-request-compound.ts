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
import type { PermissionRequest } from './permission-request';

/**
 * @type PermissionRequestCompound
 * A Permission Object and children to create a complete structure
 * @export
 */
/*export type PermissionRequestCompound = PermissionRequest;*/
export interface PermissionRequestCompound {
    /**
     * The unique ID of the Permission
     * @type {number}
     * @memberof PermissionRequestCompound
     */
    pkiPermissionID?:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof PermissionRequestCompound
     */
    fkiUserID?:number 
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof PermissionRequestCompound
     */
    fkiApikeyID?:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof PermissionRequestCompound
     */
    fkiUsergroupID?:number 
    /**
     * The unique ID of the Company
     * @type {number}
     * @memberof PermissionRequestCompound
     */
    fkiCompanyID?:number 
    /**
     * The unique ID of the Modulesection
     * @type {number}
     * @memberof PermissionRequestCompound
     */
    fkiModulesectionID:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PermissionRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPermissionRequestCompound
 */
export class DataObjectPermissionRequestCompound {
    pkiPermissionID?:number = undefined
    fkiUserID?:number = undefined
    fkiApikeyID?:number = undefined
    fkiUsergroupID?:number = undefined
    fkiCompanyID?:number = undefined
    fkiModulesectionID:number = 0
}

/**
 * @export 
 * A PermissionRequestCompound Validation Object
 * @class ValidationObjectPermissionRequestCompound
 */
export class ValidationObjectPermissionRequestCompound {
   pkiPermissionID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
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
} 


