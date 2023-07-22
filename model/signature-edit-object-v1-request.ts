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
import { SignatureRequestCompound } from './signature-request-compound';

/**
 * Request for PUT /1/object/signature/{pkiSignatureID}
 * @export
 * @interface SignatureEditObjectV1Request
 */
export interface SignatureEditObjectV1Request {
    /**
     * 
     * @type {SignatureRequestCompound}
     * @memberof SignatureEditObjectV1Request
     */
    'objSignature': SignatureRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectSignatureRequestCompound } from './'
// @ts-ignore
import { ValidationObjectSignatureRequestCompound } from './'

/**
 * @export 
 * A SignatureEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSignatureEditObjectV1Request
 */
export class DataObjectSignatureEditObjectV1Request {
   objSignature:SignatureRequestCompound = new DataObjectSignatureRequestCompound()
}

/**
 * @export 
 * A SignatureEditObjectV1Request Validation Object
 * @class ValidationObjectSignatureEditObjectV1Request
 */
export class ValidationObjectSignatureEditObjectV1Request {
   objSignature = new ValidationObjectSignatureRequestCompound()
} 


