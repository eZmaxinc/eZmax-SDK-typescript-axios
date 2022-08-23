/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Payload for GET /1/object/notificationtest/{pkiNotificationtestID}/getElements
 * @export
 * @interface NotificationtestGetElementsV1ResponseMPayload
 */
export interface NotificationtestGetElementsV1ResponseMPayload {
    /**
     * The unique ID of the Notificationtest
     * @type {number}
     * @memberof NotificationtestGetElementsV1ResponseMPayload
     */
    'pkiNotificationtestID': number;
    /**
     * The function name of the Notificationtest
     * @type {string}
     * @memberof NotificationtestGetElementsV1ResponseMPayload
     */
    'sNotificationtestFunction': string;
    /**
     * 
     * @type {Array<string>}
     * @memberof NotificationtestGetElementsV1ResponseMPayload
     */
    'a_sVariableobjectProperty'?: Array<string>;
    /**
     * 
     * @type {Array<{ [key: string]: any; }>}
     * @memberof NotificationtestGetElementsV1ResponseMPayload
     */
    'a_objVariableobject': Array<{ [key: string]: any; }>;
}

