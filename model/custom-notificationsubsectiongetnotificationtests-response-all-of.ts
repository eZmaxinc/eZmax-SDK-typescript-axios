/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomNotificationtestgetnotificationtestsResponse } from './custom-notificationtestgetnotificationtests-response';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface CustomNotificationsubsectiongetnotificationtestsResponseAllOf
 */
export interface CustomNotificationsubsectiongetnotificationtestsResponseAllOf {
    /**
     * 
     * @type {Array<CustomNotificationtestgetnotificationtestsResponse>}
     * @memberof CustomNotificationsubsectiongetnotificationtestsResponseAllOf
     */
    'a_objNotificationtest': Array<CustomNotificationtestgetnotificationtestsResponse>;
}
/**
 * A CustomNotificationsubsectiongetnotificationtestsResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomNotificationsubsectiongetnotificationtestsResponseAllOf
 */
export class DefaultObjectCustomNotificationsubsectiongetnotificationtestsResponseAllOf extends DefaultObject {
   a_objNotificationtest:Array<CustomNotificationtestgetnotificationtestsResponse> = []
}


