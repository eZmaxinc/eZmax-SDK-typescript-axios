/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Generic Error Message
 * @export
 * @interface CommonResponseError
 */
export interface CommonResponseError {
    /**
     * More detail about the error
     * @type {string}
     * @memberof CommonResponseError
     */
    'sErrorMessage': string;
    /**
     * The error code. See documentation for valid values
     * @type {string}
     * @memberof CommonResponseError
     */
    'eErrorCode': string;
}
/**
 * A CommonResponseError Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonResponseError
 */
export class DefaultObjectCommonResponseError extends DefaultObject {
   sErrorMessage:string = ''
   eErrorCode:string = ''
}


