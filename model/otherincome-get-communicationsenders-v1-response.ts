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
import type { OtherincomeGetCommunicationsendersV1ResponseMPayload } from './otherincome-get-communicationsenders-v1-response-mpayload';

/**
 * @type OtherincomeGetCommunicationsendersV1Response
 * Response for GET /1/object/otherincome/{pkiOtherincomeID}/getCommunicationrecipients
 * @export
 */
/*export type OtherincomeGetCommunicationsendersV1Response = CommonResponse;*/
export interface OtherincomeGetCommunicationsendersV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof OtherincomeGetCommunicationsendersV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof OtherincomeGetCommunicationsendersV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {OtherincomeGetCommunicationsendersV1ResponseMPayload}
     * @memberof OtherincomeGetCommunicationsendersV1Response
     */
    mPayload:OtherincomeGetCommunicationsendersV1ResponseMPayload 
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
import { DataObjectOtherincomeGetCommunicationsendersV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectOtherincomeGetCommunicationsendersV1ResponseMPayload } from './'

/**
 * @export 
 * A OtherincomeGetCommunicationsendersV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectOtherincomeGetCommunicationsendersV1Response
 */
export class DataObjectOtherincomeGetCommunicationsendersV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:OtherincomeGetCommunicationsendersV1ResponseMPayload = new DataObjectOtherincomeGetCommunicationsendersV1ResponseMPayload()
}

/**
 * @export 
 * A OtherincomeGetCommunicationsendersV1Response Validation Object
 * @class ValidationObjectOtherincomeGetCommunicationsendersV1Response
 */
export class ValidationObjectOtherincomeGetCommunicationsendersV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectOtherincomeGetCommunicationsendersV1ResponseMPayload()
} 


