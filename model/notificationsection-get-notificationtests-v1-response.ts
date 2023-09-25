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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { NotificationsectionGetNotificationtestsV1ResponseMPayload } from './notificationsection-get-notificationtests-v1-response-mpayload';

/**
 * @type NotificationsectionGetNotificationtestsV1Response
 * Response for GET /1/object/notificationsection/{pkiNotificationsectionID}/getNotificationtests
 * @export
 */
/** export type NotificationsectionGetNotificationtestsV1Response = CommonResponse; */
export interface NotificationsectionGetNotificationtestsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof NotificationsectionGetNotificationtestsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof NotificationsectionGetNotificationtestsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {NotificationsectionGetNotificationtestsV1ResponseMPayload}
     * @memberof NotificationsectionGetNotificationtestsV1Response
     */
    mPayload:NotificationsectionGetNotificationtestsV1ResponseMPayload 
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
import { DataObjectNotificationsectionGetNotificationtestsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectNotificationsectionGetNotificationtestsV1ResponseMPayload } from './'

/**
 * @export 
 * A NotificationsectionGetNotificationtestsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectNotificationsectionGetNotificationtestsV1Response
 */
export class DataObjectNotificationsectionGetNotificationtestsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:NotificationsectionGetNotificationtestsV1ResponseMPayload = new DataObjectNotificationsectionGetNotificationtestsV1ResponseMPayload()
}

/**
 * @export 
 * A NotificationsectionGetNotificationtestsV1Response Validation Object
 * @class ValidationObjectNotificationsectionGetNotificationtestsV1Response
 */
export class ValidationObjectNotificationsectionGetNotificationtestsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectNotificationsectionGetNotificationtestsV1ResponseMPayload()
} 


