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



import { DefaultObject } from '../base'

/**
 * Name of the Notificationsubsection
 * @export
 * @interface MultilingualNotificationsubsectionName
 */
export interface MultilingualNotificationsubsectionName {
    /**
     * The name of the Notificationsubsection in French
     * @type {string}
     * @memberof MultilingualNotificationsubsectionName
     */
    'sNotificationsubsectionName1'?: string;
    /**
     * The name of the Notificationsubsection in English
     * @type {string}
     * @memberof MultilingualNotificationsubsectionName
     */
    'sNotificationsubsectionName2'?: string;
}
/**
 * A MultilingualNotificationsubsectionName Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectMultilingualNotificationsubsectionName
 */
export class DefaultObjectMultilingualNotificationsubsectionName extends DefaultObject {
   sNotificationsubsectionName1?:string = undefined
   sNotificationsubsectionName2?:string = undefined
}


