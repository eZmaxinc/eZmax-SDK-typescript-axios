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
import { SignatureRequest } from './signature-request';

/**
 * @type SignatureRequestCompound
 * A Signature Object and children
 * @export
 */
export type SignatureRequestCompound = SignatureRequest;


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
    tSignatureSvg:string = ''
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
   tSignatureSvg = {
      type: 'string',
      pattern: '/^.{0,32767}$/',
      required: true
   }
} 


