/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Signature Object
 * @export
 * @interface SignatureRequest
 */
export interface SignatureRequest {
    /**
     * The unique ID of the Signature
     * @type {number}
     * @memberof SignatureRequest
     */
    'pkiSignatureID'?: number;
    /**
     * The svg of the Signature
     * @type {string}
     * @memberof SignatureRequest
     */
    'tSignatureSvg': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SignatureRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSignatureRequest
 */
export class DataObjectSignatureRequest {
   pkiSignatureID?:number = undefined
   tSignatureSvg:string = ''
}

/**
 * @export 
 * A SignatureRequest Validation Object
 * @class ValidationObjectSignatureRequest
 */
export class ValidationObjectSignatureRequest {
   pkiSignatureID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   tSignatureSvg = {
      type: 'string',
      pattern: '/^.{0,32767}$/',
      required: true
   }
} 

