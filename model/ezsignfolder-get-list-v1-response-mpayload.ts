/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
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
import type { EzsignfolderListElement } from './ezsignfolder-list-element';

/**
 * @type EzsignfolderGetListV1ResponseMPayload
 * Payload for GET /1/object/ezsignfolder/getList
 * @export
 */
/*export type EzsignfolderGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;*/
export interface EzsignfolderGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof EzsignfolderGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof EzsignfolderGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<EzsignfolderListElement>}
     * @memberof EzsignfolderGetListV1ResponseMPayload
     */
    a_objEzsignfolder:Array<EzsignfolderListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetListV1ResponseMPayload
 */
export class DataObjectEzsignfolderGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objEzsignfolder:Array<EzsignfolderListElement> = []
}

/**
 * @export 
 * A EzsignfolderGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderGetListV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objEzsignfolder = {
      type: 'array',
      required: true
   }
} 


