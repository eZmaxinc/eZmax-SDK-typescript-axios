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
import { ClonehistoryGetListV1ResponseMPayloadAllOf } from './clonehistory-get-list-v1-response-mpayload-all-of';
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
export type ClonehistoryGetListV1ResponseMPayload = ClonehistoryGetListV1ResponseMPayloadAllOf & CommonGetListV1ResponseMPayload;


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
   a_objClonehistory:Array<ClonehistoryListElement> = []
   iRowReturned:number = 0
   iRowFiltered:number = 0
}

/**
 * @export 
 * A ClonehistoryGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectClonehistoryGetListV1ResponseMPayload
 */
export class ValidationObjectClonehistoryGetListV1ResponseMPayload {
   a_objClonehistory = {
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


