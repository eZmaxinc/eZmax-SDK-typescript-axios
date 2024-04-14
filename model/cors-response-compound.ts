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


// May contain unused imports in some cases
// @ts-ignore
import { CorsResponse } from './cors-response';

/**
 * @type CorsResponseCompound
 * A Cors Object
 * @export
 */
/*export type CorsResponseCompound = CorsResponse;*/
export interface CorsResponseCompound {
    /**
     * The unique ID of the Cors
     * @type {number}
     * @memberof CorsResponseCompound
     */
    pkiCorsID:number 
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof CorsResponseCompound
     */
    fkiApikeyID:number 
    /**
     * The entryurl of the Cors
     * @type {string}
     * @memberof CorsResponseCompound
     */
    sCorsEntryurl:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CorsResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCorsResponseCompound
 */
export class DataObjectCorsResponseCompound {
    pkiCorsID:number = 0
    fkiApikeyID:number = 0
    sCorsEntryurl:string = ''
}

/**
 * @export 
 * A CorsResponseCompound Validation Object
 * @class ValidationObjectCorsResponseCompound
 */
export class ValidationObjectCorsResponseCompound {
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
      pattern: '/^(https|http):\\/\\/[^\s\\/$.?#].[^\s]*$/',
      required: true
   }
} 


