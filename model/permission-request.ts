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



/**
 * A Permission Object
 * @export
 * @interface PermissionRequest
 */
export interface PermissionRequest {
    /**
     * The unique ID of the Permission
     * @type {number}
     * @memberof PermissionRequest
     */
    /*'pkiPermissionID'?: number;*/
    'pkiPermissionID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof PermissionRequest
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof PermissionRequest
     */
    /*'fkiApikeyID'?: number;*/
    'fkiApikeyID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof PermissionRequest
     */
    /*'fkiUsergroupID'?: number;*/
    'fkiUsergroupID'?: number;
    /**
     * The unique ID of the Company
     * @type {number}
     * @memberof PermissionRequest
     */
    /*'fkiCompanyID'?: number;*/
    'fkiCompanyID'?: number;
    /**
     * The unique ID of the Modulesection
     * @type {number}
     * @memberof PermissionRequest
     */
    /*'fkiModulesectionID': number;*/
    'fkiModulesectionID': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PermissionRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPermissionRequest
 */
export class DataObjectPermissionRequest {
   pkiPermissionID?:number = undefined
   fkiUserID?:number = undefined
   fkiApikeyID?:number = undefined
   fkiUsergroupID?:number = undefined
   fkiCompanyID?:number = undefined
   fkiModulesectionID:number = 0
}

/**
 * @export 
 * A PermissionRequest Validation Object
 * @class ValidationObjectPermissionRequest
 */
export class ValidationObjectPermissionRequest {
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


