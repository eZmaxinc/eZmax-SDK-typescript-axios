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
import type { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { TranqcontractGetCommunicationListV1ResponseMPayload } from './tranqcontract-get-communication-list-v1-response-mpayload';

/**
 * @type TranqcontractGetCommunicationListV1Response
 * Response for GET /1/object/tranqcontract/{pkiTranqcontractID}/getCommunicationList
 * @export
 */
/*export type TranqcontractGetCommunicationListV1Response = CommonResponseGetList;*/
export interface TranqcontractGetCommunicationListV1Response {
    /**
     * 
     * @type {TranqcontractGetCommunicationListV1ResponseMPayload}
     * @memberof TranqcontractGetCommunicationListV1Response
     */
    mPayload:TranqcontractGetCommunicationListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectTranqcontractGetCommunicationListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectTranqcontractGetCommunicationListV1ResponseMPayload } from './'

/**
 * @export 
 * A TranqcontractGetCommunicationListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectTranqcontractGetCommunicationListV1Response
 */
export class DataObjectTranqcontractGetCommunicationListV1Response {
    mPayload:TranqcontractGetCommunicationListV1ResponseMPayload = new DataObjectTranqcontractGetCommunicationListV1ResponseMPayload()
}

/**
 * @export 
 * A TranqcontractGetCommunicationListV1Response Validation Object
 * @class ValidationObjectTranqcontractGetCommunicationListV1Response
 */
export class ValidationObjectTranqcontractGetCommunicationListV1Response {
   mPayload = new ValidationObjectTranqcontractGetCommunicationListV1ResponseMPayload()
} 


