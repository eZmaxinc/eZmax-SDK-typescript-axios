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
 * @interface CorsResponse
 */
export interface CorsResponse {
    /**
     * The unique ID of the Cors
     * @type {number}
     * @memberof CorsResponse
     */
    /*'pkiCorsID': number;*/
    'pkiCorsID': number;
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof CorsResponse
     */
    /*'fkiApikeyID': number;*/
    'fkiApikeyID': number;
    /**
     * The entryurl of the Cors
     * @type {string}
     * @memberof CorsResponse
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
 * A CorsResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCorsResponse
 */
export class DataObjectCorsResponse {
   pkiCorsID:number = 0
   fkiApikeyID:number = 0
   sCorsEntryurl:string = ''
}

/**
 * @export 
 * A CorsResponse Validation Object
 * @class ValidationObjectCorsResponse
 */
export class ValidationObjectCorsResponse {
   pkiCorsID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
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


