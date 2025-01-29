/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Usergroupmembership Object
 * @export
 * @interface UsergroupmembershipRequest
 */
export interface UsergroupmembershipRequest {
    /**
     * The unique ID of the Usergroupmembership
     * @type {number}
     * @memberof UsergroupmembershipRequest
     */
    /*'pkiUsergroupmembershipID'?: number;*/
    'pkiUsergroupmembershipID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof UsergroupmembershipRequest
     */
    /*'fkiUsergroupID': number;*/
    'fkiUsergroupID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UsergroupmembershipRequest
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Usergroupexternal
     * @type {number}
     * @memberof UsergroupmembershipRequest
     */
    /*'fkiUsergroupexternalID'?: number;*/
    'fkiUsergroupexternalID'?: number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupmembershipRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupmembershipRequest
 */
export class DataObjectUsergroupmembershipRequest {
   pkiUsergroupmembershipID?:number = undefined
   fkiUsergroupID:number = 0
   fkiUserID?:number = undefined
   fkiUsergroupexternalID?:number = undefined
}

/**
 * @export 
 * A UsergroupmembershipRequest Validation Object
 * @class ValidationObjectUsergroupmembershipRequest
 */
export class ValidationObjectUsergroupmembershipRequest {
   pkiUsergroupmembershipID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUsergroupexternalID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
} 


