/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { NotificationsectionGetNotificationtestsV1ResponseMPayload } from './notificationsection-get-notificationtests-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface NotificationsectionGetNotificationtestsV1ResponseAllOf
 */
export interface NotificationsectionGetNotificationtestsV1ResponseAllOf {
    /**
     * 
     * @type {NotificationsectionGetNotificationtestsV1ResponseMPayload}
     * @memberof NotificationsectionGetNotificationtestsV1ResponseAllOf
     */
    'mPayload': NotificationsectionGetNotificationtestsV1ResponseMPayload;
}
/**
 * A NotificationsectionGetNotificationtestsV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectNotificationsectionGetNotificationtestsV1ResponseAllOf
 */
export class DefaultObjectNotificationsectionGetNotificationtestsV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<NotificationsectionGetNotificationtestsV1ResponseMPayload> = {}
}


