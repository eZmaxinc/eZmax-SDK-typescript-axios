/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
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
import { NotificationtestGetElementsV1ResponseAllOf } from './notificationtest-get-elements-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { NotificationtestGetElementsV1ResponseMPayload } from './notificationtest-get-elements-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type NotificationtestGetElementsV1Response
 * Response for GET /1/object/notificationtest/{pkiNotificationtestID}/getElements
 * @export
 */
export type NotificationtestGetElementsV1Response = CommonResponse & NotificationtestGetElementsV1ResponseAllOf;


/**
 * @export 
 * A NotificationtestGetElementsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectNotificationtestGetElementsV1Response
 */
export class DefaultObjectNotificationtestGetElementsV1Response extends DefaultObject {
   mPayload:Partial<NotificationtestGetElementsV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


