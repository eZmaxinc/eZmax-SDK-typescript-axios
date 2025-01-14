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
import { CommunicationSendV1ResponseMPayload } from './communication-send-v1-response-mpayload';

/**
 * @type CommunicationSendV1Response
 * Response for POST /1/object/communication
 * @export
 */
/*export type CommunicationSendV1Response = CommonResponse;*/
export interface CommunicationSendV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof CommunicationSendV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof CommunicationSendV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {CommunicationSendV1ResponseMPayload}
     * @memberof CommunicationSendV1Response
     */
    mPayload:CommunicationSendV1ResponseMPayload 
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
import { DataObjectCommunicationSendV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectCommunicationSendV1ResponseMPayload } from './'

/**
 * @export 
 * A CommunicationSendV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationSendV1Response
 */
export class DataObjectCommunicationSendV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:CommunicationSendV1ResponseMPayload = new DataObjectCommunicationSendV1ResponseMPayload()
}

/**
 * @export 
 * A CommunicationSendV1Response Validation Object
 * @class ValidationObjectCommunicationSendV1Response
 */
export class ValidationObjectCommunicationSendV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectCommunicationSendV1ResponseMPayload()
} 


