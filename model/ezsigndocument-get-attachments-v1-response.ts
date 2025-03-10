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
import type { EzsigndocumentGetAttachmentsV1ResponseMPayload } from './ezsigndocument-get-attachments-v1-response-mpayload';

/**
 * @type EzsigndocumentGetAttachmentsV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getAttachments
 * @export
 */
/*export type EzsigndocumentGetAttachmentsV1Response = CommonResponse;*/
export interface EzsigndocumentGetAttachmentsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndocumentGetAttachmentsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndocumentGetAttachmentsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigndocumentGetAttachmentsV1ResponseMPayload}
     * @memberof EzsigndocumentGetAttachmentsV1Response
     */
    mPayload:EzsigndocumentGetAttachmentsV1ResponseMPayload 
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
import { DataObjectEzsigndocumentGetAttachmentsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetAttachmentsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentGetAttachmentsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetAttachmentsV1Response
 */
export class DataObjectEzsigndocumentGetAttachmentsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigndocumentGetAttachmentsV1ResponseMPayload = new DataObjectEzsigndocumentGetAttachmentsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentGetAttachmentsV1Response Validation Object
 * @class ValidationObjectEzsigndocumentGetAttachmentsV1Response
 */
export class ValidationObjectEzsigndocumentGetAttachmentsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigndocumentGetAttachmentsV1ResponseMPayload()
} 


