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
import { CommonResponseError } from './common-response-error';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseErrorSTemporaryFileUrlAllOf } from './common-response-error-stemporary-file-url-all-of';

/**
 * @type CommonResponseErrorSTemporaryFileUrl
 * Generic Error Message
 * @export
 */
export type CommonResponseErrorSTemporaryFileUrl = CommonResponseError & CommonResponseErrorSTemporaryFileUrlAllOf;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonResponseErrorSTemporaryFileUrl Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonResponseErrorSTemporaryFileUrl
 */
export class DataObjectCommonResponseErrorSTemporaryFileUrl {
   sTemporaryFileUrl?:string = undefined
   sErrorMessage:string = ''
   eErrorCode:string = ''
}

/**
 * @export 
 * A CommonResponseErrorSTemporaryFileUrl Validation Object
 * @class ValidationObjectCommonResponseErrorSTemporaryFileUrl
 */
export class ValidationObjectCommonResponseErrorSTemporaryFileUrl {
   sTemporaryFileUrl = {
      type: 'string',
      required: false
   }
   sErrorMessage = {
      type: 'string',
      required: true
   }
   eErrorCode = {
      type: 'string',
      required: true
   }
} 


