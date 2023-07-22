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
import { UserListElement } from './user-list-element';

/**
 * 
 * @export
 * @interface UserGetListV1ResponseMPayloadAllOf
 */
export interface UserGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<UserListElement>}
     * @memberof UserGetListV1ResponseMPayloadAllOf
     */
    'a_objUser': Array<UserListElement>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserGetListV1ResponseMPayloadAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetListV1ResponseMPayloadAllOf
 */
export class DataObjectUserGetListV1ResponseMPayloadAllOf {
   a_objUser:Array<UserListElement> = []
}

/**
 * @export 
 * A UserGetListV1ResponseMPayloadAllOf Validation Object
 * @class ValidationObjectUserGetListV1ResponseMPayloadAllOf
 */
export class ValidationObjectUserGetListV1ResponseMPayloadAllOf {
   a_objUser = {
      type: 'array',
      required: true
   }
} 


