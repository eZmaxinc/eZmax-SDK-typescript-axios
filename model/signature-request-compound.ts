/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldESignaturePreference } from './field-esignature-preference';
// May contain unused imports in some cases
// @ts-ignore
import { SignatureRequest } from './signature-request';

/**
 * @type SignatureRequestCompound
 * A Signature Object and children
 * @export
 */
/*export type SignatureRequestCompound = SignatureRequest;*/
export interface SignatureRequestCompound {
    /**
     * The unique ID of the Signature
     * @type {number}
     * @memberof SignatureRequestCompound
     */
    pkiSignatureID?:number 
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof SignatureRequestCompound
     */
    fkiFontID:number 
    /**
     * 
     * @type {FieldESignaturePreference}
     * @memberof SignatureRequestCompound
     */
    eSignaturePreference:FieldESignaturePreference 
    /**
     * The svg of the Signature
     * @type {string}
     * @memberof SignatureRequestCompound
     */
    tSignatureSvg?:string 
    /**
     * The svg of the Initials
     * @type {string}
     * @memberof SignatureRequestCompound
     */
    tSignatureSvginitials?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SignatureRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSignatureRequestCompound
 */
export class DataObjectSignatureRequestCompound {
    pkiSignatureID?:number = undefined
    fkiFontID:number = 0
    eSignaturePreference:FieldESignaturePreference = 'Text'
    tSignatureSvg?:string = undefined
    tSignatureSvginitials?:string = undefined
}

/**
 * @export 
 * A SignatureRequestCompound Validation Object
 * @class ValidationObjectSignatureRequestCompound
 */
export class ValidationObjectSignatureRequestCompound {
   pkiSignatureID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiFontID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   eSignaturePreference = {
      type: 'enum',
      allowableValues: ['Text','Handwritten'],
      required: true
   }
   tSignatureSvg = {
      type: 'string',
      pattern: /^.{60,65535}$/,
      required: false
   }
   tSignatureSvginitials = {
      type: 'string',
      pattern: /^.{60,65535}$/,
      required: false
   }
} 


