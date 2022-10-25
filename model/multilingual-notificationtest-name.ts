/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Name of the Notificationtest
 * @export
 * @interface MultilingualNotificationtestName
 */
export interface MultilingualNotificationtestName {
    /**
     * The name of the Notificationtest in French
     * @type {string}
     * @memberof MultilingualNotificationtestName
     */
    'sNotificationtestName1'?: string;
    /**
     * The name of the Notificationtest in English
     * @type {string}
     * @memberof MultilingualNotificationtestName
     */
    'sNotificationtestName2'?: string;
}
/**
 * A MultilingualNotificationtestName Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectMultilingualNotificationtestName
 */
export class DefaultObjectMultilingualNotificationtestName extends DefaultObject {
   sNotificationtestName1?:string = undefined
   sNotificationtestName2?:string = undefined
}


