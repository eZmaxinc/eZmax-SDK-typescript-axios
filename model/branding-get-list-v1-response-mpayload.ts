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
import { BrandingListElement } from './branding-list-element';
// May contain unused imports in some cases
// @ts-ignore
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';

/**
 * @type BrandingGetListV1ResponseMPayload
 * Payload for GET /1/object/branding/getList
 * @export
 */
export type BrandingGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BrandingGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingGetListV1ResponseMPayload
 */
export class DataObjectBrandingGetListV1ResponseMPayload {
    iRowReturned:number = 0
    iRowFiltered:number = 0
    a_objBranding:Array<BrandingListElement> = []
}

/**
 * @export 
 * A BrandingGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectBrandingGetListV1ResponseMPayload
 */
export class ValidationObjectBrandingGetListV1ResponseMPayload {
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
   a_objBranding = {
      type: 'array',
      required: true
   }
} 


