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
import type { InscriptionGetAttachmentsV1ResponseMPayload } from './inscription-get-attachments-v1-response-mpayload';

/**
 * @type InscriptionGetAttachmentsV1Response
 * Response for GET /1/object/inscription/{pkiInscriptionID}/getAttachments
 * @export
 */
/*export type InscriptionGetAttachmentsV1Response = CommonResponse;*/
export interface InscriptionGetAttachmentsV1Response {
    /**
     * 
     * @type {InscriptionGetAttachmentsV1ResponseMPayload}
     * @memberof InscriptionGetAttachmentsV1Response
     */
    mPayload:InscriptionGetAttachmentsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectInscriptionGetAttachmentsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectInscriptionGetAttachmentsV1ResponseMPayload } from './'

/**
 * @export 
 * A InscriptionGetAttachmentsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInscriptionGetAttachmentsV1Response
 */
export class DataObjectInscriptionGetAttachmentsV1Response {
    mPayload:InscriptionGetAttachmentsV1ResponseMPayload = new DataObjectInscriptionGetAttachmentsV1ResponseMPayload()
}

/**
 * @export 
 * A InscriptionGetAttachmentsV1Response Validation Object
 * @class ValidationObjectInscriptionGetAttachmentsV1Response
 */
export class ValidationObjectInscriptionGetAttachmentsV1Response {
   mPayload = new ValidationObjectInscriptionGetAttachmentsV1ResponseMPayload()
} 


