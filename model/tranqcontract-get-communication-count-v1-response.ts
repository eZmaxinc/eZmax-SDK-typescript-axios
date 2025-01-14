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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { TranqcontractGetCommunicationCountV1ResponseMPayload } from './tranqcontract-get-communication-count-v1-response-mpayload';

/**
 * @type TranqcontractGetCommunicationCountV1Response
 * Response for GET /1/object/tranqcontract/{pkiTranqcontractID}/getCommunicationCount
 * @export
 */
/*export type TranqcontractGetCommunicationCountV1Response = CommonResponse;*/
export interface TranqcontractGetCommunicationCountV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof TranqcontractGetCommunicationCountV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof TranqcontractGetCommunicationCountV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {TranqcontractGetCommunicationCountV1ResponseMPayload}
     * @memberof TranqcontractGetCommunicationCountV1Response
     */
    mPayload:TranqcontractGetCommunicationCountV1ResponseMPayload 
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
import { DataObjectTranqcontractGetCommunicationCountV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectTranqcontractGetCommunicationCountV1ResponseMPayload } from './'

/**
 * @export 
 * A TranqcontractGetCommunicationCountV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectTranqcontractGetCommunicationCountV1Response
 */
export class DataObjectTranqcontractGetCommunicationCountV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:TranqcontractGetCommunicationCountV1ResponseMPayload = new DataObjectTranqcontractGetCommunicationCountV1ResponseMPayload()
}

/**
 * @export 
 * A TranqcontractGetCommunicationCountV1Response Validation Object
 * @class ValidationObjectTranqcontractGetCommunicationCountV1Response
 */
export class ValidationObjectTranqcontractGetCommunicationCountV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectTranqcontractGetCommunicationCountV1ResponseMPayload()
} 


