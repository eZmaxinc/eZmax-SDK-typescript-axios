/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CustomNotificationsubsectiongetnotificationtestsResponse } from './custom-notificationsubsectiongetnotificationtests-response';

/**
 * Payload for GET /1/object/notificationsection/{pkiNotificationsectionID}/getNotificationtests
 * @export
 * @interface NotificationsectionGetNotificationtestsV1ResponseMPayload
 */
export interface NotificationsectionGetNotificationtestsV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomNotificationsubsectiongetnotificationtestsResponse>}
     * @memberof NotificationsectionGetNotificationtestsV1ResponseMPayload
     */
    'a_objNotificationsubsection': Array<CustomNotificationsubsectiongetnotificationtestsResponse>;
}

