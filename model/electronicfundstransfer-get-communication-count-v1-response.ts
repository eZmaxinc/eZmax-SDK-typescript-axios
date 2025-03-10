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
import type { ElectronicfundstransferGetCommunicationCountV1ResponseMPayload } from './electronicfundstransfer-get-communication-count-v1-response-mpayload';

/**
 * @type ElectronicfundstransferGetCommunicationCountV1Response
 * Response for GET /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationCount
 * @export
 */
/*export type ElectronicfundstransferGetCommunicationCountV1Response = CommonResponse;*/
export interface ElectronicfundstransferGetCommunicationCountV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof ElectronicfundstransferGetCommunicationCountV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof ElectronicfundstransferGetCommunicationCountV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {ElectronicfundstransferGetCommunicationCountV1ResponseMPayload}
     * @memberof ElectronicfundstransferGetCommunicationCountV1Response
     */
    mPayload:ElectronicfundstransferGetCommunicationCountV1ResponseMPayload 
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
import { DataObjectElectronicfundstransferGetCommunicationCountV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectElectronicfundstransferGetCommunicationCountV1ResponseMPayload } from './'

/**
 * @export 
 * A ElectronicfundstransferGetCommunicationCountV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectElectronicfundstransferGetCommunicationCountV1Response
 */
export class DataObjectElectronicfundstransferGetCommunicationCountV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:ElectronicfundstransferGetCommunicationCountV1ResponseMPayload = new DataObjectElectronicfundstransferGetCommunicationCountV1ResponseMPayload()
}

/**
 * @export 
 * A ElectronicfundstransferGetCommunicationCountV1Response Validation Object
 * @class ValidationObjectElectronicfundstransferGetCommunicationCountV1Response
 */
export class ValidationObjectElectronicfundstransferGetCommunicationCountV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectElectronicfundstransferGetCommunicationCountV1ResponseMPayload()
} 


