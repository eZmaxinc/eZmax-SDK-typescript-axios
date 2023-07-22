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
 * A Userstaged List Element
 * @export
 * @interface UserstagedListElement
 */
export interface UserstagedListElement {
    /**
     * The unique ID of the Userstaged
     * @type {number}
     * @memberof UserstagedListElement
     */
    'pkiUserstagedID': number;
    /**
     * The email address.
     * @type {string}
     * @memberof UserstagedListElement
     */
    'sEmailAddress': string;
    /**
     * The firstname of the Userstaged
     * @type {string}
     * @memberof UserstagedListElement
     */
    'sUserstagedFirstname': string;
    /**
     * The lastname of the Userstaged
     * @type {string}
     * @memberof UserstagedListElement
     */
    'sUserstagedLastname': string;
    /**
     * The externalid of the Userstaged
     * @type {string}
     * @memberof UserstagedListElement
     */
    'sUserstagedExternalid': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserstagedListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedListElement
 */
export class DataObjectUserstagedListElement {
   pkiUserstagedID:number = 0
   sEmailAddress:string = ''
   sUserstagedFirstname:string = ''
   sUserstagedLastname:string = ''
   sUserstagedExternalid:string = ''
}

/**
 * @export 
 * A UserstagedListElement Validation Object
 * @class ValidationObjectUserstagedListElement
 */
export class ValidationObjectUserstagedListElement {
   pkiUserstagedID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: true
   }
   sEmailAddress = {
      type: 'string',
      required: true
   }
   sUserstagedFirstname = {
      type: 'string',
      pattern: '/^.{0,20}$/',
      required: true
   }
   sUserstagedLastname = {
      type: 'string',
      pattern: '/^.{0,25}$/',
      required: true
   }
   sUserstagedExternalid = {
      type: 'string',
      pattern: '/^.{1,60}$/',
      required: true
   }
} 


