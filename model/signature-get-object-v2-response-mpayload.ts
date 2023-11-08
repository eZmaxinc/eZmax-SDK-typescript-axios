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


// May contain unused imports in some cases
// @ts-ignore
import { SignatureResponseCompound } from './signature-response-compound';

/**
 * Payload for GET /2/object/signature/{pkiSignatureID}
 * @export
 * @interface SignatureGetObjectV2ResponseMPayload
 */
export interface SignatureGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {SignatureResponseCompound}
     * @memberof SignatureGetObjectV2ResponseMPayload
     */
    'objSignature': SignatureResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectSignatureResponseCompound } from './'
// @ts-ignore
import { ValidationObjectSignatureResponseCompound } from './'

/**
 * @export 
 * A SignatureGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSignatureGetObjectV2ResponseMPayload
 */
export class DataObjectSignatureGetObjectV2ResponseMPayload {
   objSignature:SignatureResponseCompound = new DataObjectSignatureResponseCompound()
}

/**
 * @export 
 * A SignatureGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectSignatureGetObjectV2ResponseMPayload
 */
export class ValidationObjectSignatureGetObjectV2ResponseMPayload {
   objSignature = new ValidationObjectSignatureResponseCompound()
} 

