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
import type { UsergroupexternalmembershipResponse } from './usergroupexternalmembership-response';

/**
 * @type UsergroupexternalmembershipResponseCompound
 * A Usergroupexternalmembership Object
 * @export
 */
/*export type UsergroupexternalmembershipResponseCompound = UsergroupexternalmembershipResponse;*/
export interface UsergroupexternalmembershipResponseCompound {
    /**
     * The unique ID of the Usergroupexternalmembership
     * @type {number}
     * @memberof UsergroupexternalmembershipResponseCompound
     */
    pkiUsergroupexternalmembershipID:number 
    /**
     * The unique ID of the Usergroupexternal
     * @type {number}
     * @memberof UsergroupexternalmembershipResponseCompound
     */
    fkiUsergroupexternalID:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UsergroupexternalmembershipResponseCompound
     */
    fkiUserID:number 
    /**
     * The first name of the user
     * @type {string}
     * @memberof UsergroupexternalmembershipResponseCompound
     */
    sUserFirstname:string 
    /**
     * The last name of the user
     * @type {string}
     * @memberof UsergroupexternalmembershipResponseCompound
     */
    sUserLastname:string 
    /**
     * The login name of the User.
     * @type {string}
     * @memberof UsergroupexternalmembershipResponseCompound
     */
    sUserLoginname:string 
    /**
     * The email address.
     * @type {string}
     * @memberof UsergroupexternalmembershipResponseCompound
     */
    sEmailAddress:string 
    /**
     * The name of the Usergroupexternal
     * @type {string}
     * @memberof UsergroupexternalmembershipResponseCompound
     */
    sUsergroupexternalName:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupexternalmembershipResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalmembershipResponseCompound
 */
export class DataObjectUsergroupexternalmembershipResponseCompound {
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
 * A UsergroupexternalmembershipResponseCompound Validation Object
 * @class ValidationObjectUsergroupexternalmembershipResponseCompound
 */
export class ValidationObjectUsergroupexternalmembershipResponseCompound {
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
      pattern: /^(?:([\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20})|([a-zA-Z0-9]){1,32})$/,
      required: true
   }
   sEmailAddress = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: true
   }
   sUsergroupexternalName = {
      type: 'string',
      pattern: /^.{0,64}$/,
      required: true
   }
} 


