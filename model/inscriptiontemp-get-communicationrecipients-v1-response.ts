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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { InscriptiontempGetCommunicationrecipientsV1ResponseMPayload } from './inscriptiontemp-get-communicationrecipients-v1-response-mpayload';

/**
 * @type InscriptiontempGetCommunicationrecipientsV1Response
 * Response for GET /1/object/inscriptiontemp/{pkiInscriptiontempID}/getCommunicationrecipients
 * @export
 */
/*export type InscriptiontempGetCommunicationrecipientsV1Response = CommonResponse;*/
export interface InscriptiontempGetCommunicationrecipientsV1Response {
    /**
     * 
     * @type {InscriptiontempGetCommunicationrecipientsV1ResponseMPayload}
     * @memberof InscriptiontempGetCommunicationrecipientsV1Response
     */
    mPayload:InscriptiontempGetCommunicationrecipientsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectInscriptiontempGetCommunicationrecipientsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectInscriptiontempGetCommunicationrecipientsV1ResponseMPayload } from './'

/**
 * @export 
 * A InscriptiontempGetCommunicationrecipientsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInscriptiontempGetCommunicationrecipientsV1Response
 */
export class DataObjectInscriptiontempGetCommunicationrecipientsV1Response {
    mPayload:InscriptiontempGetCommunicationrecipientsV1ResponseMPayload = new DataObjectInscriptiontempGetCommunicationrecipientsV1ResponseMPayload()
}

/**
 * @export 
 * A InscriptiontempGetCommunicationrecipientsV1Response Validation Object
 * @class ValidationObjectInscriptiontempGetCommunicationrecipientsV1Response
 */
export class ValidationObjectInscriptiontempGetCommunicationrecipientsV1Response {
   mPayload = new ValidationObjectInscriptiontempGetCommunicationrecipientsV1ResponseMPayload()
} 


