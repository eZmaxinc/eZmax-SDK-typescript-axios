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



/**
 * Generic Warning Message
 * @export
 * @interface CommonResponseWarning
 */
export interface CommonResponseWarning {
    /**
     * More detail about the warning
     * @type {string}
     * @memberof CommonResponseWarning
     */
    /*'sWarningMessage': string;*/
    'sWarningMessage': string;
    /**
     * The warning code. See documentation for valid values
     * @type {string}
     * @memberof CommonResponseWarning
     */
    /*'eWarningCode': string;*/
    'eWarningCode': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonResponseWarning Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonResponseWarning
 */
export class DataObjectCommonResponseWarning {
   sWarningMessage:string = ''
   eWarningCode:string = ''
}

/**
 * @export 
 * A CommonResponseWarning Validation Object
 * @class ValidationObjectCommonResponseWarning
 */
export class ValidationObjectCommonResponseWarning {
   sWarningMessage = {
      type: 'string',
      required: true
   }
   eWarningCode = {
      type: 'string',
      required: true
   }
} 


