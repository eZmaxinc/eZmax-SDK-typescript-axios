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
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendGetListV1ResponseMPayloadAllOf } from './ezsignbulksend-get-list-v1-response-mpayload-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendListElement } from './ezsignbulksend-list-element';

/**
 * @type EzsignbulksendGetListV1ResponseMPayload
 * Payload for GET /1/object/ezsignbulksend/getList
 * @export
 */
export type EzsignbulksendGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload & EzsignbulksendGetListV1ResponseMPayloadAllOf;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendGetListV1ResponseMPayload
 */
export class DataObjectEzsignbulksendGetListV1ResponseMPayload {
   a_objEzsignbulksend:Array<EzsignbulksendListElement> = []
   iRowReturned:number = 0
   iRowFiltered:number = 0
}

/**
 * @export 
 * A EzsignbulksendGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksendGetListV1ResponseMPayload
 */
export class ValidationObjectEzsignbulksendGetListV1ResponseMPayload {
   a_objEzsignbulksend = {
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


