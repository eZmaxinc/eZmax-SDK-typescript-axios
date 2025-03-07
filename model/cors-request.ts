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
 * A Cors Object
 * @export
 * @interface CorsRequest
 */
export interface CorsRequest {
    /**
     * The unique ID of the Cors
     * @type {number}
     * @memberof CorsRequest
     */
    /*'pkiCorsID'?: number;*/
    'pkiCorsID'?: number;
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof CorsRequest
     */
    /*'fkiApikeyID': number;*/
    'fkiApikeyID': number;
    /**
     * The entryurl of the Cors
     * @type {string}
     * @memberof CorsRequest
     */
    /*'sCorsEntryurl': string;*/
    'sCorsEntryurl': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CorsRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCorsRequest
 */
export class DataObjectCorsRequest {
   pkiCorsID?:number = undefined
   fkiApikeyID:number = 0
   sCorsEntryurl:string = ''
}

/**
 * @export 
 * A CorsRequest Validation Object
 * @class ValidationObjectCorsRequest
 */
export class ValidationObjectCorsRequest {
   pkiCorsID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiApikeyID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sCorsEntryurl = {
      type: 'string',
      pattern: /^(https|http):\/\/[^\s\/$.?#].[^\s]*$/,
      required: true
   }
} 


