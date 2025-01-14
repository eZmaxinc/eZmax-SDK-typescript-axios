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
 * A Usergroupexternal List Element
 * @export
 * @interface UsergroupexternalListElement
 */
export interface UsergroupexternalListElement {
    /**
     * The unique ID of the Usergroupexternal
     * @type {number}
     * @memberof UsergroupexternalListElement
     */
    /*'pkiUsergroupexternalID': number;*/
    'pkiUsergroupexternalID': number;
    /**
     * The name of the Usergroupexternal
     * @type {string}
     * @memberof UsergroupexternalListElement
     */
    /*'sUsergroupexternalName': string;*/
    'sUsergroupexternalName': string;
    /**
     * The id of the Usergroupexternal
     * @type {string}
     * @memberof UsergroupexternalListElement
     */
    /*'sUsergroupexternalID': string;*/
    'sUsergroupexternalID': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupexternalListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalListElement
 */
export class DataObjectUsergroupexternalListElement {
   pkiUsergroupexternalID:number = 0
   sUsergroupexternalName:string = ''
   sUsergroupexternalID:string = ''
}

/**
 * @export 
 * A UsergroupexternalListElement Validation Object
 * @class ValidationObjectUsergroupexternalListElement
 */
export class ValidationObjectUsergroupexternalListElement {
   pkiUsergroupexternalID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sUsergroupexternalName = {
      type: 'string',
      pattern: /^.{0,64}$/,
      required: true
   }
   sUsergroupexternalID = {
      type: 'string',
      pattern: /^.{0,64}$/,
      required: true
   }
} 


