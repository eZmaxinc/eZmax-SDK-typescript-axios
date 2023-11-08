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
import { UserResponseCompound } from './user-response-compound';

/**
 * Payload for GET /2/object/user/{pkiUserID}
 * @export
 * @interface UserGetObjectV2ResponseMPayload
 */
export interface UserGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {UserResponseCompound}
     * @memberof UserGetObjectV2ResponseMPayload
     */
    'objUser': UserResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserResponseCompound } from './'
// @ts-ignore
import { ValidationObjectUserResponseCompound } from './'

/**
 * @export 
 * A UserGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetObjectV2ResponseMPayload
 */
export class DataObjectUserGetObjectV2ResponseMPayload {
   objUser:UserResponseCompound = new DataObjectUserResponseCompound()
}

/**
 * @export 
 * A UserGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectUserGetObjectV2ResponseMPayload
 */
export class ValidationObjectUserGetObjectV2ResponseMPayload {
   objUser = new ValidationObjectUserResponseCompound()
} 

