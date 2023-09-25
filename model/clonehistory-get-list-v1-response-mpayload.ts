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
import { ClonehistoryListElement } from './clonehistory-list-element';
// May contain unused imports in some cases
// @ts-ignore
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';

/**
 * @type ClonehistoryGetListV1ResponseMPayload
 * Payload for GET /1/object/clonehistory/getList
 * @export
 */
/** export type ClonehistoryGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload; */
export interface ClonehistoryGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof ClonehistoryGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof ClonehistoryGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<ClonehistoryListElement>}
     * @memberof ClonehistoryGetListV1ResponseMPayload
     */
    a_objClonehistory:Array<ClonehistoryListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ClonehistoryGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectClonehistoryGetListV1ResponseMPayload
 */
export class DataObjectClonehistoryGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objClonehistory:Array<ClonehistoryListElement> = []
}

/**
 * @export 
 * A ClonehistoryGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectClonehistoryGetListV1ResponseMPayload
 */
export class ValidationObjectClonehistoryGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objClonehistory = {
      type: 'array',
      required: true
   }
} 


