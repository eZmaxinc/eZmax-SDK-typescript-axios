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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { NotificationtestGetElementsV1ResponseMPayload } from './notificationtest-get-elements-v1-response-mpayload';

/**
 * @type NotificationtestGetElementsV1Response
 * Response for GET /1/object/notificationtest/{pkiNotificationtestID}/getElements
 * @export
 */
/*export type NotificationtestGetElementsV1Response = CommonResponse;*/
export interface NotificationtestGetElementsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof NotificationtestGetElementsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof NotificationtestGetElementsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {NotificationtestGetElementsV1ResponseMPayload}
     * @memberof NotificationtestGetElementsV1Response
     */
    mPayload:NotificationtestGetElementsV1ResponseMPayload 
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
import { DataObjectNotificationtestGetElementsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectNotificationtestGetElementsV1ResponseMPayload } from './'

/**
 * @export 
 * A NotificationtestGetElementsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectNotificationtestGetElementsV1Response
 */
export class DataObjectNotificationtestGetElementsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:NotificationtestGetElementsV1ResponseMPayload = new DataObjectNotificationtestGetElementsV1ResponseMPayload()
}

/**
 * @export 
 * A NotificationtestGetElementsV1Response Validation Object
 * @class ValidationObjectNotificationtestGetElementsV1Response
 */
export class ValidationObjectNotificationtestGetElementsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectNotificationtestGetElementsV1ResponseMPayload()
} 


