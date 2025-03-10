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
import type { UsergroupdelegationResponse } from './usergroupdelegation-response';

/**
 * @type UsergroupdelegationResponseCompound
 * A Usergroupdelegation Object
 * @export
 */
/*export type UsergroupdelegationResponseCompound = UsergroupdelegationResponse;*/
export interface UsergroupdelegationResponseCompound {
    /**
     * The unique ID of the Usergroupdelegation
     * @type {number}
     * @memberof UsergroupdelegationResponseCompound
     */
    pkiUsergroupdelegationID:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof UsergroupdelegationResponseCompound
     */
    fkiUsergroupID:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UsergroupdelegationResponseCompound
     */
    fkiUserID:number 
    /**
     * The first name of the user
     * @type {string}
     * @memberof UsergroupdelegationResponseCompound
     */
    sUserFirstname:string 
    /**
     * The last name of the user
     * @type {string}
     * @memberof UsergroupdelegationResponseCompound
     */
    sUserLastname:string 
    /**
     * The login name of the User.
     * @type {string}
     * @memberof UsergroupdelegationResponseCompound
     */
    sUserLoginname:string 
    /**
     * The email address.
     * @type {string}
     * @memberof UsergroupdelegationResponseCompound
     */
    sEmailAddress?:string 
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof UsergroupdelegationResponseCompound
     */
    sUsergroupNameX:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupdelegationResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupdelegationResponseCompound
 */
export class DataObjectUsergroupdelegationResponseCompound {
    pkiUsergroupdelegationID:number = 0
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
 * A UsergroupdelegationResponseCompound Validation Object
 * @class ValidationObjectUsergroupdelegationResponseCompound
 */
export class ValidationObjectUsergroupdelegationResponseCompound {
   pkiUsergroupdelegationID = {
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
      pattern: /^(?:([\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20})|([a-zA-Z0-9]){1,32})$/,
      required: true
   }
   sEmailAddress = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: false
   }
   sUsergroupNameX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
} 


