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
 * A Usergroupmembership Object
 * @export
 * @interface UsergroupmembershipResponse
 */
export interface UsergroupmembershipResponse {
    /**
     * The unique ID of the Usergroupmembership
     * @type {number}
     * @memberof UsergroupmembershipResponse
     */
    'pkiUsergroupmembershipID': number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof UsergroupmembershipResponse
     */
    'fkiUsergroupID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UsergroupmembershipResponse
     */
    'fkiUserID': number;
    /**
     * The first name of the user
     * @type {string}
     * @memberof UsergroupmembershipResponse
     */
    'sUserFirstname': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof UsergroupmembershipResponse
     */
    'sUserLastname': string;
    /**
     * The login name of the User.
     * @type {string}
     * @memberof UsergroupmembershipResponse
     */
    'sUserLoginname': string;
    /**
     * The email address.
     * @type {string}
     * @memberof UsergroupmembershipResponse
     */
    'sEmailAddress'?: string;
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof UsergroupmembershipResponse
     */
    'sUsergroupNameX': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupmembershipResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupmembershipResponse
 */
export class DataObjectUsergroupmembershipResponse {
   pkiUsergroupmembershipID:number = 0
   fkiUsergroupID:number = 0
   fkiUserID:number = 0
   sUserFirstname:string = ''
   sUserLastname:string = ''
   sUserLoginname:string = ''
   sEmailAddress?:string = undefined
   sUsergroupNameX:string = ''
}

/**
 * @export 
 * A UsergroupmembershipResponse Validation Object
 * @class ValidationObjectUsergroupmembershipResponse
 */
export class ValidationObjectUsergroupmembershipResponse {
   pkiUsergroupmembershipID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
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
      required: true
   }
   sUserFirstname = {
      type: 'string',
      required: true
   }
   sUserLastname = {
      type: 'string',
      required: true
   }
   sUserLoginname = {
      type: 'string',
      pattern: '/^(?:([\w\.-]+@[\w\.-]+\.\w{2,4})|([a-zA-Z0-9]){1,32})$/',
      required: true
   }
   sEmailAddress = {
      type: 'string',
      required: false
   }
   sUsergroupNameX = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: true
   }
} 


