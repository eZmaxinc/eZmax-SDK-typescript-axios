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
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { UsergroupListElement } from './usergroup-list-element';

/**
 * @type UsergroupGetListV1ResponseMPayload
 * Payload for GET /1/object/usergroup/getList
 * @export
 */
/** export type UsergroupGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload; */
export interface UsergroupGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof UsergroupGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof UsergroupGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<UsergroupListElement>}
     * @memberof UsergroupGetListV1ResponseMPayload
     */
    a_objUsergroup:Array<UsergroupListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupGetListV1ResponseMPayload
 */
export class DataObjectUsergroupGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objUsergroup:Array<UsergroupListElement> = []
}

/**
 * @export 
 * A UsergroupGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupGetListV1ResponseMPayload
 */
export class ValidationObjectUsergroupGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objUsergroup = {
      type: 'array',
      required: true
   }
} 


