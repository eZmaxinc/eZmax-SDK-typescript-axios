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
import { AuthenticationexternalRequestCompound } from './authenticationexternal-request-compound';

/**
 * Request for PUT /1/object/authenticationexternal/{pkiAuthenticationexternalID}
 * @export
 * @interface AuthenticationexternalEditObjectV1Request
 */
export interface AuthenticationexternalEditObjectV1Request {
    /**
     * 
     * @type {AuthenticationexternalRequestCompound}
     * @memberof AuthenticationexternalEditObjectV1Request
     */
    /*'objAuthenticationexternal': AuthenticationexternalRequestCompound;*/
    'objAuthenticationexternal': AuthenticationexternalRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectAuthenticationexternalRequestCompound } from './'
// @ts-ignore
import { ValidationObjectAuthenticationexternalRequestCompound } from './'

/**
 * @export 
 * A AuthenticationexternalEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAuthenticationexternalEditObjectV1Request
 */
export class DataObjectAuthenticationexternalEditObjectV1Request {
   objAuthenticationexternal:AuthenticationexternalRequestCompound = new DataObjectAuthenticationexternalRequestCompound()
}

/**
 * @export 
 * A AuthenticationexternalEditObjectV1Request Validation Object
 * @class ValidationObjectAuthenticationexternalEditObjectV1Request
 */
export class ValidationObjectAuthenticationexternalEditObjectV1Request {
   objAuthenticationexternal = new ValidationObjectAuthenticationexternalRequestCompound()
} 


