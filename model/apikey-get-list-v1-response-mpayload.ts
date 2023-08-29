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
import { ApikeyListElement } from './apikey-list-element';
// May contain unused imports in some cases
// @ts-ignore
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';

/**
 * @type ApikeyGetListV1ResponseMPayload
 * Payload for GET /1/object/apikey/getList
 * @export
 */
export type ApikeyGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ApikeyGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyGetListV1ResponseMPayload
 */
export class DataObjectApikeyGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objApikey:Array<ApikeyListElement> = []
}

/**
 * @export 
 * A ApikeyGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectApikeyGetListV1ResponseMPayload
 */
export class ValidationObjectApikeyGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objApikey = {
      type: 'array',
      required: true
   }
} 


