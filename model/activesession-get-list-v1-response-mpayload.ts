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
import { ActivesessionListElement } from './activesession-list-element';
// May contain unused imports in some cases
// @ts-ignore
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';

/**
 * @type ActivesessionGetListV1ResponseMPayload
 * Payload for GET /1/object/activesession/getList
 * @export
 */
/** export type ActivesessionGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload; */
export interface ActivesessionGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof ActivesessionGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof ActivesessionGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<ActivesessionListElement>}
     * @memberof ActivesessionGetListV1ResponseMPayload
     */
    a_objActivesession:Array<ActivesessionListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ActivesessionGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionGetListV1ResponseMPayload
 */
export class DataObjectActivesessionGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objActivesession:Array<ActivesessionListElement> = []
}

/**
 * @export 
 * A ActivesessionGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectActivesessionGetListV1ResponseMPayload
 */
export class ValidationObjectActivesessionGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objActivesession = {
      type: 'array',
      required: true
   }
} 

