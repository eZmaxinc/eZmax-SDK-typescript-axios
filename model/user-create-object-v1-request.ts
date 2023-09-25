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
import { UserRequestCompound } from './user-request-compound';

/**
 * Request for POST /1/object/user
 * @export
 * @interface UserCreateObjectV1Request
 */
export interface UserCreateObjectV1Request {
    /**
     * 
     * @type {Array<UserRequestCompound>}
     * @memberof UserCreateObjectV1Request
     */
    'a_objUser': Array<UserRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserCreateObjectV1Request
 */
export class DataObjectUserCreateObjectV1Request {
   a_objUser:Array<UserRequestCompound> = []
}

/**
 * @export 
 * A UserCreateObjectV1Request Validation Object
 * @class ValidationObjectUserCreateObjectV1Request
 */
export class ValidationObjectUserCreateObjectV1Request {
   a_objUser = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


