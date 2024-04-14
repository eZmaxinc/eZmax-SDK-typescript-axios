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
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { UserListElement } from './user-list-element';

/**
 * @type UserGetListV1ResponseMPayload
 * Payload for GET /1/object/user/getList
 * @export
 */
/*export type UserGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;*/
export interface UserGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof UserGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof UserGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<UserListElement>}
     * @memberof UserGetListV1ResponseMPayload
     */
    a_objUser:Array<UserListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetListV1ResponseMPayload
 */
export class DataObjectUserGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objUser:Array<UserListElement> = []
}

/**
 * @export 
 * A UserGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectUserGetListV1ResponseMPayload
 */
export class ValidationObjectUserGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objUser = {
      type: 'array',
      required: true
   }
} 


