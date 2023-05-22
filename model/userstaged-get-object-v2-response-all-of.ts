/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { UserstagedGetObjectV2ResponseMPayload } from './userstaged-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface UserstagedGetObjectV2ResponseAllOf
 */
export interface UserstagedGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {UserstagedGetObjectV2ResponseMPayload}
     * @memberof UserstagedGetObjectV2ResponseAllOf
     */
    'mPayload': UserstagedGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserstagedGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUserstagedGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A UserstagedGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedGetObjectV2ResponseAllOf
 */
export class DataObjectUserstagedGetObjectV2ResponseAllOf {
   mPayload:UserstagedGetObjectV2ResponseMPayload = new DataObjectUserstagedGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A UserstagedGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectUserstagedGetObjectV2ResponseAllOf
 */
export class ValidationObjectUserstagedGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectUserstagedGetObjectV2ResponseMPayload()
} 


