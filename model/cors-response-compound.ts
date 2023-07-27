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


// May contain unused imports in some cases
// @ts-ignore
import { CorsResponse } from './cors-response';

/**
 * @type CorsResponseCompound
 * A Cors Object
 * @export
 */
export type CorsResponseCompound = CorsResponse;


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
      pattern: '/^.{0,2048}$/',
      required: true
   }
} 


