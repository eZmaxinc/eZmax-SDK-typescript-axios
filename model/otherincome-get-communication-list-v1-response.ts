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
import type { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { OtherincomeGetCommunicationListV1ResponseMPayload } from './otherincome-get-communication-list-v1-response-mpayload';

/**
 * @type OtherincomeGetCommunicationListV1Response
 * Response for GET /1/object/otherincome/{pkiOtherincomeID}/getCommunicationList
 * @export
 */
/*export type OtherincomeGetCommunicationListV1Response = CommonResponseGetList;*/
export interface OtherincomeGetCommunicationListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof OtherincomeGetCommunicationListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof OtherincomeGetCommunicationListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {OtherincomeGetCommunicationListV1ResponseMPayload}
     * @memberof OtherincomeGetCommunicationListV1Response
     */
    mPayload:OtherincomeGetCommunicationListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectOtherincomeGetCommunicationListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectOtherincomeGetCommunicationListV1ResponseMPayload } from './'

/**
 * @export 
 * A OtherincomeGetCommunicationListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectOtherincomeGetCommunicationListV1Response
 */
export class DataObjectOtherincomeGetCommunicationListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:OtherincomeGetCommunicationListV1ResponseMPayload = new DataObjectOtherincomeGetCommunicationListV1ResponseMPayload()
}

/**
 * @export 
 * A OtherincomeGetCommunicationListV1Response Validation Object
 * @class ValidationObjectOtherincomeGetCommunicationListV1Response
 */
export class ValidationObjectOtherincomeGetCommunicationListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectOtherincomeGetCommunicationListV1ResponseMPayload()
} 


