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


// May contain unused imports in some cases
// @ts-ignore
import type { AuthenticationexternalRequestCompound } from './authenticationexternal-request-compound';

/**
 * Request for POST /1/object/authenticationexternal
 * @export
 * @interface AuthenticationexternalCreateObjectV1Request
 */
export interface AuthenticationexternalCreateObjectV1Request {
    /**
     * 
     * @type {Array<AuthenticationexternalRequestCompound>}
     * @memberof AuthenticationexternalCreateObjectV1Request
     */
    /*'a_objAuthenticationexternal': Array<AuthenticationexternalRequestCompound>;*/
    'a_objAuthenticationexternal': Array<AuthenticationexternalRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A AuthenticationexternalCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAuthenticationexternalCreateObjectV1Request
 */
export class DataObjectAuthenticationexternalCreateObjectV1Request {
   a_objAuthenticationexternal:Array<AuthenticationexternalRequestCompound> = []
}

/**
 * @export 
 * A AuthenticationexternalCreateObjectV1Request Validation Object
 * @class ValidationObjectAuthenticationexternalCreateObjectV1Request
 */
export class ValidationObjectAuthenticationexternalCreateObjectV1Request {
   a_objAuthenticationexternal = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


