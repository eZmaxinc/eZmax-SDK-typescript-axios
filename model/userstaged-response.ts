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
 * A Userstaged Object
 * @export
 * @interface UserstagedResponse
 */
export interface UserstagedResponse {
    /**
     * The unique ID of the Userstaged
     * @type {number}
     * @memberof UserstagedResponse
     */
    /*'pkiUserstagedID': number;*/
    'pkiUserstagedID': number;
    /**
     * The unique ID of the Email
     * @type {number}
     * @memberof UserstagedResponse
     */
    /*'fkiEmailID': number;*/
    'fkiEmailID': number;
    /**
     * The email address.
     * @type {string}
     * @memberof UserstagedResponse
     */
    /*'sEmailAddress': string;*/
    'sEmailAddress': string;
    /**
     * The firstname of the Userstaged
     * @type {string}
     * @memberof UserstagedResponse
     */
    /*'sUserstagedFirstname': string;*/
    'sUserstagedFirstname': string;
    /**
     * The lastname of the Userstaged
     * @type {string}
     * @memberof UserstagedResponse
     */
    /*'sUserstagedLastname': string;*/
    'sUserstagedLastname': string;
    /**
     * The externalid of the Userstaged
     * @type {string}
     * @memberof UserstagedResponse
     */
    /*'sUserstagedExternalid': string;*/
    'sUserstagedExternalid': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserstagedResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedResponse
 */
export class DataObjectUserstagedResponse {
   pkiUserstagedID:number = 0
   fkiEmailID:number = 0
   sEmailAddress:string = ''
   sUserstagedFirstname:string = ''
   sUserstagedLastname:string = ''
   sUserstagedExternalid:string = ''
}

/**
 * @export 
 * A UserstagedResponse Validation Object
 * @class ValidationObjectUserstagedResponse
 */
export class ValidationObjectUserstagedResponse {
   pkiUserstagedID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: true
   }
   fkiEmailID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: true
   }
   sEmailAddress = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: true
   }
   sUserstagedFirstname = {
      type: 'string',
      pattern: /^.{0,20}$/,
      required: true
   }
   sUserstagedLastname = {
      type: 'string',
      pattern: /^.{0,25}$/,
      required: true
   }
   sUserstagedExternalid = {
      type: 'string',
      pattern: /^.{1,60}$/,
      required: true
   }
} 


