/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
import { EzsigntemplateListElement } from './ezsigntemplate-list-element';

/**
 * @type EzsigntemplateGetListV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplate/getList
 * @export
 */
export type EzsigntemplateGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateGetListV1ResponseMPayload
 */
export class DataObjectEzsigntemplateGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objEzsigntemplate:Array<EzsigntemplateListElement> = []
}

/**
 * @export 
 * A EzsigntemplateGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplateGetListV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplateGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objEzsigntemplate = {
      type: 'array',
      required: true
   }
} 


