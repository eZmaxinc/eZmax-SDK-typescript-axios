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
import type { RejectedoffertopurchaseGetCommunicationrecipientsV1ResponseMPayload } from './rejectedoffertopurchase-get-communicationrecipients-v1-response-mpayload';

/**
 * @type RejectedoffertopurchaseGetCommunicationrecipientsV1Response
 * Response for GET /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/getCommunicationrecipients
 * @export
 */
/*export type RejectedoffertopurchaseGetCommunicationrecipientsV1Response = CommonResponse;*/
export interface RejectedoffertopurchaseGetCommunicationrecipientsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof RejectedoffertopurchaseGetCommunicationrecipientsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof RejectedoffertopurchaseGetCommunicationrecipientsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {RejectedoffertopurchaseGetCommunicationrecipientsV1ResponseMPayload}
     * @memberof RejectedoffertopurchaseGetCommunicationrecipientsV1Response
     */
    mPayload:RejectedoffertopurchaseGetCommunicationrecipientsV1ResponseMPayload 
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
import { DataObjectRejectedoffertopurchaseGetCommunicationrecipientsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectRejectedoffertopurchaseGetCommunicationrecipientsV1ResponseMPayload } from './'

/**
 * @export 
 * A RejectedoffertopurchaseGetCommunicationrecipientsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectRejectedoffertopurchaseGetCommunicationrecipientsV1Response
 */
export class DataObjectRejectedoffertopurchaseGetCommunicationrecipientsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:RejectedoffertopurchaseGetCommunicationrecipientsV1ResponseMPayload = new DataObjectRejectedoffertopurchaseGetCommunicationrecipientsV1ResponseMPayload()
}

/**
 * @export 
 * A RejectedoffertopurchaseGetCommunicationrecipientsV1Response Validation Object
 * @class ValidationObjectRejectedoffertopurchaseGetCommunicationrecipientsV1Response
 */
export class ValidationObjectRejectedoffertopurchaseGetCommunicationrecipientsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectRejectedoffertopurchaseGetCommunicationrecipientsV1ResponseMPayload()
} 


