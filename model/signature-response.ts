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
 * A Signature Object
 * @export
 * @interface SignatureResponse
 */
export interface SignatureResponse {
    /**
     * The unique ID of the Signature
     * @type {number}
     * @memberof SignatureResponse
     */
    /*'pkiSignatureID': number;*/
    'pkiSignatureID': number;
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof SignatureResponse
     */
    /*'fkiFontID'?: number;*/
    'fkiFontID'?: number;
    /**
     * The URL of the SVG file for the Signature
     * @type {string}
     * @memberof SignatureResponse
     */
    /*'sSignatureUrl'?: string;*/
    'sSignatureUrl'?: string;
    /**
     * The URL of the SVG file for the Initials
     * @type {string}
     * @memberof SignatureResponse
     */
    /*'sSignatureUrlinitials'?: string;*/
    'sSignatureUrlinitials'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SignatureResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSignatureResponse
 */
export class DataObjectSignatureResponse {
   pkiSignatureID:number = 0
   fkiFontID?:number = undefined
   sSignatureUrl?:string = undefined
   sSignatureUrlinitials?:string = undefined
}

/**
 * @export 
 * A SignatureResponse Validation Object
 * @class ValidationObjectSignatureResponse
 */
export class ValidationObjectSignatureResponse {
   pkiSignatureID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiFontID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sSignatureUrl = {
      type: 'string',
      pattern: /^(https|http):\/\/[^\s\/$.?#].[^\s]*$/,
      required: false
   }
   sSignatureUrlinitials = {
      type: 'string',
      pattern: /^(https|http):\/\/[^\s\/$.?#].[^\s]*$/,
      required: false
   }
} 


