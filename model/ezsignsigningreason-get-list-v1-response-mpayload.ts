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
import { EzsignsigningreasonListElement } from './ezsignsigningreason-list-element';

/**
 * @type EzsignsigningreasonGetListV1ResponseMPayload
 * Payload for GET /1/object/ezsignsigningreason/getList
 * @export
 */
/*export type EzsignsigningreasonGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;*/
export interface EzsignsigningreasonGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof EzsignsigningreasonGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof EzsignsigningreasonGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<EzsignsigningreasonListElement>}
     * @memberof EzsignsigningreasonGetListV1ResponseMPayload
     */
    a_objEzsignsigningreason:Array<EzsignsigningreasonListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsigningreasonGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsigningreasonGetListV1ResponseMPayload
 */
export class DataObjectEzsignsigningreasonGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objEzsignsigningreason:Array<EzsignsigningreasonListElement> = []
}

/**
 * @export 
 * A EzsignsigningreasonGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignsigningreasonGetListV1ResponseMPayload
 */
export class ValidationObjectEzsignsigningreasonGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objEzsignsigningreason = {
      type: 'array',
      required: true
   }
} 


