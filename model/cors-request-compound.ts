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
import type { CorsRequest } from './cors-request';

/**
 * @type CorsRequestCompound
 * A Cors Object and children
 * @export
 */
/*export type CorsRequestCompound = CorsRequest;*/
export interface CorsRequestCompound {
    /**
     * The unique ID of the Cors
     * @type {number}
     * @memberof CorsRequestCompound
     */
    pkiCorsID?:number 
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof CorsRequestCompound
     */
    fkiApikeyID:number 
    /**
     * The entryurl of the Cors
     * @type {string}
     * @memberof CorsRequestCompound
     */
    sCorsEntryurl:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CorsRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCorsRequestCompound
 */
export class DataObjectCorsRequestCompound {
    pkiCorsID?:number = undefined
    fkiApikeyID:number = 0
    sCorsEntryurl:string = ''
}

/**
 * @export 
 * A CorsRequestCompound Validation Object
 * @class ValidationObjectCorsRequestCompound
 */
export class ValidationObjectCorsRequestCompound {
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


