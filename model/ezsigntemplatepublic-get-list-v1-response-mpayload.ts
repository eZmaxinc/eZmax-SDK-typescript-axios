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
import type { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepublicListElement } from './ezsigntemplatepublic-list-element';

/**
 * @type EzsigntemplatepublicGetListV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplatepublic/getList
 * @export
 */
/*export type EzsigntemplatepublicGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;*/
export interface EzsigntemplatepublicGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof EzsigntemplatepublicGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof EzsigntemplatepublicGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<EzsigntemplatepublicListElement>}
     * @memberof EzsigntemplatepublicGetListV1ResponseMPayload
     */
    a_objEzsigntemplatepublic:Array<EzsigntemplatepublicListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepublicGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicGetListV1ResponseMPayload
 */
export class DataObjectEzsigntemplatepublicGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objEzsigntemplatepublic:Array<EzsigntemplatepublicListElement> = []
}

/**
 * @export 
 * A EzsigntemplatepublicGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepublicGetListV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepublicGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objEzsigntemplatepublic = {
      type: 'array',
      required: true
   }
} 


