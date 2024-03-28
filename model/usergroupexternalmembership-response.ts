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



/**
 * A Usergroupexternalmembership Object
 * @export
 * @interface UsergroupexternalmembershipResponse
 */
export interface UsergroupexternalmembershipResponse {
    /**
     * The unique ID of the Usergroupexternalmembership
     * @type {number}
     * @memberof UsergroupexternalmembershipResponse
     */
    'pkiUsergroupexternalmembershipID': number;
    /**
     * The unique ID of the Usergroupexternal
     * @type {number}
     * @memberof UsergroupexternalmembershipResponse
     */
    'fkiUsergroupexternalID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UsergroupexternalmembershipResponse
     */
    'fkiUserID': number;
    /**
     * The first name of the user
     * @type {string}
     * @memberof UsergroupexternalmembershipResponse
     */
    'sUserFirstname': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof UsergroupexternalmembershipResponse
     */
    'sUserLastname': string;
    /**
     * The login name of the User.
     * @type {string}
     * @memberof UsergroupexternalmembershipResponse
     */
    'sUserLoginname': string;
    /**
     * The email address.
     * @type {string}
     * @memberof UsergroupexternalmembershipResponse
     */
    'sEmailAddress': string;
    /**
     * The name of the Usergroupexternal
     * @type {string}
     * @memberof UsergroupexternalmembershipResponse
     */
    'sUsergroupexternalName': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupexternalmembershipResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalmembershipResponse
 */
export class DataObjectUsergroupexternalmembershipResponse {
   pkiUsergroupexternalmembershipID:number = 0
   fkiUsergroupexternalID:number = 0
   fkiUserID:number = 0
   sUserFirstname:string = ''
   sUserLastname:string = ''
   sUserLoginname:string = ''
   sEmailAddress:string = ''
   sUsergroupexternalName:string = ''
}

/**
 * @export 
 * A UsergroupexternalmembershipResponse Validation Object
 * @class ValidationObjectUsergroupexternalmembershipResponse
 */
export class ValidationObjectUsergroupexternalmembershipResponse {
   pkiUsergroupexternalmembershipID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiUsergroupexternalID = {
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
      pattern: '/^(?:([\w\.-]+@[\w\.-]+\.\w{2,20})|([a-zA-Z0-9]){1,32})$/',
      required: true
   }
   sEmailAddress = {
      type: 'string',
      required: true
   }
   sUsergroupexternalName = {
      type: 'string',
      pattern: '/^.{0,64}$/',
      required: true
   }
} 


