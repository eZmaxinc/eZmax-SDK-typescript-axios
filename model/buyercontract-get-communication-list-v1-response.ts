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
import type { BuyercontractGetCommunicationListV1ResponseMPayload } from './buyercontract-get-communication-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';

/**
 * @type BuyercontractGetCommunicationListV1Response
 * Response for GET /1/object/buyercontract/{pkiBuyercontractID}/getCommunicationList
 * @export
 */
/*export type BuyercontractGetCommunicationListV1Response = CommonResponseGetList;*/
export interface BuyercontractGetCommunicationListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof BuyercontractGetCommunicationListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof BuyercontractGetCommunicationListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {BuyercontractGetCommunicationListV1ResponseMPayload}
     * @memberof BuyercontractGetCommunicationListV1Response
     */
    mPayload:BuyercontractGetCommunicationListV1ResponseMPayload 
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
import { DataObjectBuyercontractGetCommunicationListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectBuyercontractGetCommunicationListV1ResponseMPayload } from './'

/**
 * @export 
 * A BuyercontractGetCommunicationListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBuyercontractGetCommunicationListV1Response
 */
export class DataObjectBuyercontractGetCommunicationListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:BuyercontractGetCommunicationListV1ResponseMPayload = new DataObjectBuyercontractGetCommunicationListV1ResponseMPayload()
}

/**
 * @export 
 * A BuyercontractGetCommunicationListV1Response Validation Object
 * @class ValidationObjectBuyercontractGetCommunicationListV1Response
 */
export class ValidationObjectBuyercontractGetCommunicationListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectBuyercontractGetCommunicationListV1ResponseMPayload()
} 


