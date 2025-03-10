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


// May contain unused imports in some cases
// @ts-ignore
import type { SignatureRequestCompound } from './signature-request-compound';

/**
 * Request for POST /1/object/signature
 * @export
 * @interface SignatureCreateObjectV1Request
 */
export interface SignatureCreateObjectV1Request {
    /**
     * 
     * @type {Array<SignatureRequestCompound>}
     * @memberof SignatureCreateObjectV1Request
     */
    /*'a_objSignature': Array<SignatureRequestCompound>;*/
    'a_objSignature': Array<SignatureRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SignatureCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSignatureCreateObjectV1Request
 */
export class DataObjectSignatureCreateObjectV1Request {
   a_objSignature:Array<SignatureRequestCompound> = []
}

/**
 * @export 
 * A SignatureCreateObjectV1Request Validation Object
 * @class ValidationObjectSignatureCreateObjectV1Request
 */
export class ValidationObjectSignatureCreateObjectV1Request {
   a_objSignature = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


