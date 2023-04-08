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

/**
 * @type CommonResponseErrorTooManyRequests
 * Generic Error Message
 * @export
 */
export type CommonResponseErrorTooManyRequests = CommonResponseError;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonResponseErrorTooManyRequests Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonResponseErrorTooManyRequests
 */
export class DataObjectCommonResponseErrorTooManyRequests {
   sErrorMessage:string = ''
   eErrorCode:string = ''
}

/**
 * @export 
 * A CommonResponseErrorTooManyRequests Validation Object
 * @class ValidationObjectCommonResponseErrorTooManyRequests
 */
export class ValidationObjectCommonResponseErrorTooManyRequests {
   sErrorMessage = {
      type: 'string',
      required: true
   }
   eErrorCode = {
      type: 'string',
      required: true
   }
} 


