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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { InvoiceGetCommunicationrecipientsV1ResponseMPayload } from './invoice-get-communicationrecipients-v1-response-mpayload';

/**
 * @type InvoiceGetCommunicationrecipientsV1Response
 * Response for GET /1/object/invoice/{pkiInvoiceID}/getCommunicationrecipients
 * @export
 */
/*export type InvoiceGetCommunicationrecipientsV1Response = CommonResponse;*/
export interface InvoiceGetCommunicationrecipientsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof InvoiceGetCommunicationrecipientsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof InvoiceGetCommunicationrecipientsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {InvoiceGetCommunicationrecipientsV1ResponseMPayload}
     * @memberof InvoiceGetCommunicationrecipientsV1Response
     */
    mPayload:InvoiceGetCommunicationrecipientsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectInvoiceGetCommunicationrecipientsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectInvoiceGetCommunicationrecipientsV1ResponseMPayload } from './'

/**
 * @export 
 * A InvoiceGetCommunicationrecipientsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInvoiceGetCommunicationrecipientsV1Response
 */
export class DataObjectInvoiceGetCommunicationrecipientsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:InvoiceGetCommunicationrecipientsV1ResponseMPayload = new DataObjectInvoiceGetCommunicationrecipientsV1ResponseMPayload()
}

/**
 * @export 
 * A InvoiceGetCommunicationrecipientsV1Response Validation Object
 * @class ValidationObjectInvoiceGetCommunicationrecipientsV1Response
 */
export class ValidationObjectInvoiceGetCommunicationrecipientsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectInvoiceGetCommunicationrecipientsV1ResponseMPayload()
} 


