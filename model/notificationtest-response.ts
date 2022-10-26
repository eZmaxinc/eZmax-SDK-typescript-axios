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
import { MultilingualNotificationtestName } from './multilingual-notificationtest-name';

import { DefaultObject } from '../base'

/**
 * A Notificationtest Object
 * @export
 * @interface NotificationtestResponse
 */
export interface NotificationtestResponse {
    /**
     * The unique ID of the Notificationtest
     * @type {number}
     * @memberof NotificationtestResponse
     */
    'pkiNotificationtestID': number;
    /**
     * 
     * @type {MultilingualNotificationtestName}
     * @memberof NotificationtestResponse
     */
    'objNotificationtestName': MultilingualNotificationtestName;
    /**
     * The unique ID of the Notificationsubsection
     * @type {number}
     * @memberof NotificationtestResponse
     */
    'fkiNotificationsubsectionID': number;
    /**
     * The function name of the Notificationtest
     * @type {string}
     * @memberof NotificationtestResponse
     */
    'sNotificationtestFunction': string;
    /**
     * The name of the Notificationtest in the language of the requester
     * @type {string}
     * @memberof NotificationtestResponse
     */
    'sNotificationtestNameX': string;
}
/**
 * A NotificationtestResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectNotificationtestResponse
 */
export class DefaultObjectNotificationtestResponse extends DefaultObject {
   pkiNotificationtestID:number = 0
   objNotificationtestName:Partial<MultilingualNotificationtestName> = {}
   fkiNotificationsubsectionID:number = 0
   sNotificationtestFunction:string = ''
   sNotificationtestNameX:string = ''
}


