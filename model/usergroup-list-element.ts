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
 * A Usergroup List Element
 * @export
 * @interface UsergroupListElement
 */
export interface UsergroupListElement {
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof UsergroupListElement
     */
    'pkiUsergroupID': number;
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof UsergroupListElement
     */
    'sUsergroupNameX': string;
    /**
     * Number of users in group
     * @type {number}
     * @memberof UsergroupListElement
     */
    'iCountUser': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupListElement
 */
export class DataObjectUsergroupListElement {
   pkiUsergroupID:number = 0
   sUsergroupNameX:string = ''
   iCountUser:number = 0
}

/**
 * @export 
 * A UsergroupListElement Validation Object
 * @class ValidationObjectUsergroupListElement
 */
export class ValidationObjectUsergroupListElement {
   pkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sUsergroupNameX = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: true
   }
   iCountUser = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
} 


