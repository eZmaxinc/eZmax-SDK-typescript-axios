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
import { CorsResponseCompound } from './cors-response-compound';

/**
 * Payload for GET /2/object/cors/{pkiCorsID}
 * @export
 * @interface CorsGetObjectV2ResponseMPayload
 */
export interface CorsGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {CorsResponseCompound}
     * @memberof CorsGetObjectV2ResponseMPayload
     */
    /*'objCors': CorsResponseCompound;*/
    'objCors': CorsResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCorsResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCorsResponseCompound } from './'

/**
 * @export 
 * A CorsGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCorsGetObjectV2ResponseMPayload
 */
export class DataObjectCorsGetObjectV2ResponseMPayload {
   objCors:CorsResponseCompound = new DataObjectCorsResponseCompound()
}

/**
 * @export 
 * A CorsGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectCorsGetObjectV2ResponseMPayload
 */
export class ValidationObjectCorsGetObjectV2ResponseMPayload {
   objCors = new ValidationObjectCorsResponseCompound()
} 


