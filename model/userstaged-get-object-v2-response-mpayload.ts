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
import { UserstagedResponseCompound } from './userstaged-response-compound';

/**
 * Payload for GET /2/object/userstaged/{pkiUserstagedID}
 * @export
 * @interface UserstagedGetObjectV2ResponseMPayload
 */
export interface UserstagedGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {UserstagedResponseCompound}
     * @memberof UserstagedGetObjectV2ResponseMPayload
     */
    'objUserstaged': UserstagedResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserstagedResponseCompound } from './'
// @ts-ignore
import { ValidationObjectUserstagedResponseCompound } from './'

/**
 * @export 
 * A UserstagedGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedGetObjectV2ResponseMPayload
 */
export class DataObjectUserstagedGetObjectV2ResponseMPayload {
   objUserstaged:UserstagedResponseCompound = new DataObjectUserstagedResponseCompound()
}

/**
 * @export 
 * A UserstagedGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectUserstagedGetObjectV2ResponseMPayload
 */
export class ValidationObjectUserstagedGetObjectV2ResponseMPayload {
   objUserstaged = new ValidationObjectUserstagedResponseCompound()
} 


