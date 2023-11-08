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
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { RejectedoffertopurchaseGetCommunicationListV1ResponseMPayload } from './rejectedoffertopurchase-get-communication-list-v1-response-mpayload';

/**
 * @type RejectedoffertopurchaseGetCommunicationListV1Response
 * Response for GET /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/getCommunicationList
 * @export
 */
/** export type RejectedoffertopurchaseGetCommunicationListV1Response = CommonResponseGetList; */
export interface RejectedoffertopurchaseGetCommunicationListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof RejectedoffertopurchaseGetCommunicationListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof RejectedoffertopurchaseGetCommunicationListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {RejectedoffertopurchaseGetCommunicationListV1ResponseMPayload}
     * @memberof RejectedoffertopurchaseGetCommunicationListV1Response
     */
    mPayload:RejectedoffertopurchaseGetCommunicationListV1ResponseMPayload 
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
import { DataObjectRejectedoffertopurchaseGetCommunicationListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectRejectedoffertopurchaseGetCommunicationListV1ResponseMPayload } from './'

/**
 * @export 
 * A RejectedoffertopurchaseGetCommunicationListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectRejectedoffertopurchaseGetCommunicationListV1Response
 */
export class DataObjectRejectedoffertopurchaseGetCommunicationListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:RejectedoffertopurchaseGetCommunicationListV1ResponseMPayload = new DataObjectRejectedoffertopurchaseGetCommunicationListV1ResponseMPayload()
}

/**
 * @export 
 * A RejectedoffertopurchaseGetCommunicationListV1Response Validation Object
 * @class ValidationObjectRejectedoffertopurchaseGetCommunicationListV1Response
 */
export class ValidationObjectRejectedoffertopurchaseGetCommunicationListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectRejectedoffertopurchaseGetCommunicationListV1ResponseMPayload()
} 


