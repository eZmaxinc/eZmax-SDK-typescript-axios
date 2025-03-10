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
import type { CorsRequestCompound } from './cors-request-compound';

/**
 * Request for POST /1/object/cors
 * @export
 * @interface CorsCreateObjectV1Request
 */
export interface CorsCreateObjectV1Request {
    /**
     * 
     * @type {Array<CorsRequestCompound>}
     * @memberof CorsCreateObjectV1Request
     */
    /*'a_objCors': Array<CorsRequestCompound>;*/
    'a_objCors': Array<CorsRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CorsCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCorsCreateObjectV1Request
 */
export class DataObjectCorsCreateObjectV1Request {
   a_objCors:Array<CorsRequestCompound> = []
}

/**
 * @export 
 * A CorsCreateObjectV1Request Validation Object
 * @class ValidationObjectCorsCreateObjectV1Request
 */
export class ValidationObjectCorsCreateObjectV1Request {
   a_objCors = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


