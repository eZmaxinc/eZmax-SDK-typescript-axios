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
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { UserstagedGetListV1ResponseMPayloadAllOf } from './userstaged-get-list-v1-response-mpayload-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { UserstagedListElement } from './userstaged-list-element';

/**
 * @type UserstagedGetListV1ResponseMPayload
 * Payload for GET /1/object/userstaged/getList
 * @export
 */
export type UserstagedGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload & UserstagedGetListV1ResponseMPayloadAllOf;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserstagedGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedGetListV1ResponseMPayload
 */
export class DataObjectUserstagedGetListV1ResponseMPayload {
    a_objUserstaged:Array<UserstagedListElement> = []
    iRowReturned:number = 0
    iRowFiltered:number = 0
}

/**
 * @export 
 * A UserstagedGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectUserstagedGetListV1ResponseMPayload
 */
export class ValidationObjectUserstagedGetListV1ResponseMPayload {
   a_objUserstaged = {
      type: 'array',
      required: true
   }
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
} 


