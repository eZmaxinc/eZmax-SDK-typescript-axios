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
import type { ElectronicfundstransferGetCommunicationsendersV1ResponseMPayload } from './electronicfundstransfer-get-communicationsenders-v1-response-mpayload';

/**
 * @type ElectronicfundstransferGetCommunicationsendersV1Response
 * Response for GET /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationrecipients
 * @export
 */
/*export type ElectronicfundstransferGetCommunicationsendersV1Response = CommonResponse;*/
export interface ElectronicfundstransferGetCommunicationsendersV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof ElectronicfundstransferGetCommunicationsendersV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof ElectronicfundstransferGetCommunicationsendersV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {ElectronicfundstransferGetCommunicationsendersV1ResponseMPayload}
     * @memberof ElectronicfundstransferGetCommunicationsendersV1Response
     */
    mPayload:ElectronicfundstransferGetCommunicationsendersV1ResponseMPayload 
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
import { DataObjectElectronicfundstransferGetCommunicationsendersV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectElectronicfundstransferGetCommunicationsendersV1ResponseMPayload } from './'

/**
 * @export 
 * A ElectronicfundstransferGetCommunicationsendersV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectElectronicfundstransferGetCommunicationsendersV1Response
 */
export class DataObjectElectronicfundstransferGetCommunicationsendersV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:ElectronicfundstransferGetCommunicationsendersV1ResponseMPayload = new DataObjectElectronicfundstransferGetCommunicationsendersV1ResponseMPayload()
}

/**
 * @export 
 * A ElectronicfundstransferGetCommunicationsendersV1Response Validation Object
 * @class ValidationObjectElectronicfundstransferGetCommunicationsendersV1Response
 */
export class ValidationObjectElectronicfundstransferGetCommunicationsendersV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectElectronicfundstransferGetCommunicationsendersV1ResponseMPayload()
} 


