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
import { NotificationtestGetElementsV1ResponseMPayload } from './notificationtest-get-elements-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface NotificationtestGetElementsV1ResponseAllOf
 */
export interface NotificationtestGetElementsV1ResponseAllOf {
    /**
     * 
     * @type {NotificationtestGetElementsV1ResponseMPayload}
     * @memberof NotificationtestGetElementsV1ResponseAllOf
     */
    'mPayload': NotificationtestGetElementsV1ResponseMPayload;
}
/**
 * A NotificationtestGetElementsV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectNotificationtestGetElementsV1ResponseAllOf
 */
export class DefaultObjectNotificationtestGetElementsV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<NotificationtestGetElementsV1ResponseMPayload> = {}
}


