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
import { EzsignfoldertypeListElement } from './ezsignfoldertype-list-element';

/**
 * @type EzsignfoldertypeGetListV1ResponseMPayload
 * Payload for GET /1/object/ezsignfoldertype/getList
 * @export
 */
/*export type EzsignfoldertypeGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;*/
export interface EzsignfoldertypeGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof EzsignfoldertypeGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof EzsignfoldertypeGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<EzsignfoldertypeListElement>}
     * @memberof EzsignfoldertypeGetListV1ResponseMPayload
     */
    a_objEzsignfoldertype:Array<EzsignfoldertypeListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldertypeGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeGetListV1ResponseMPayload
 */
export class DataObjectEzsignfoldertypeGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objEzsignfoldertype:Array<EzsignfoldertypeListElement> = []
}

/**
 * @export 
 * A EzsignfoldertypeGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfoldertypeGetListV1ResponseMPayload
 */
export class ValidationObjectEzsignfoldertypeGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objEzsignfoldertype = {
      type: 'array',
      required: true
   }
} 


