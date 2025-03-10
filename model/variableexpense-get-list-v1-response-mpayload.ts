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
import type { VariableexpenseListElement } from './variableexpense-list-element';

/**
 * @type VariableexpenseGetListV1ResponseMPayload
 * Payload for GET /1/object/variableexpense/getList
 * @export
 */
/*export type VariableexpenseGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;*/
export interface VariableexpenseGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof VariableexpenseGetListV1ResponseMPayload
     */
    iRowReturned:number 
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof VariableexpenseGetListV1ResponseMPayload
     */
    iRowFiltered:number 
    /**
     * 
     * @type {Array<VariableexpenseListElement>}
     * @memberof VariableexpenseGetListV1ResponseMPayload
     */
    a_objVariableexpense:Array<VariableexpenseListElement> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A VariableexpenseGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseGetListV1ResponseMPayload
 */
export class DataObjectVariableexpenseGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objVariableexpense:Array<VariableexpenseListElement> = []
}

/**
 * @export 
 * A VariableexpenseGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectVariableexpenseGetListV1ResponseMPayload
 */
export class ValidationObjectVariableexpenseGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objVariableexpense = {
      type: 'array',
      required: true
   }
} 


