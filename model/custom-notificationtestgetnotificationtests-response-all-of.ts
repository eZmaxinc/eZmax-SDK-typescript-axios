/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { FieldENotificationpreferenceStatus } from './field-enotificationpreference-status';

/**
 * 
 * @export
 * @interface CustomNotificationtestgetnotificationtestsResponseAllOf
 */
export interface CustomNotificationtestgetnotificationtestsResponseAllOf {
    /**
     * 
     * @type {FieldENotificationpreferenceStatus}
     * @memberof CustomNotificationtestgetnotificationtestsResponseAllOf
     */
    'eNotificationpreferenceStatus': FieldENotificationpreferenceStatus;
    /**
     * The number of elements returned by the Notificationtest
     * @type {number}
     * @memberof CustomNotificationtestgetnotificationtestsResponseAllOf
     */
    'iNotificationtest': number;
}

