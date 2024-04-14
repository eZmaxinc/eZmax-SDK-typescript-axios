/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



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
    /*'sNotificationtestName1'?: string;*/
    'sNotificationtestName1'?: string;
    /**
     * The name of the Notificationtest in English
     * @type {string}
     * @memberof MultilingualNotificationtestName
     */
    /*'sNotificationtestName2'?: string;*/
    'sNotificationtestName2'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A MultilingualNotificationtestName Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectMultilingualNotificationtestName
 */
export class DataObjectMultilingualNotificationtestName {
   sNotificationtestName1?:string = undefined
   sNotificationtestName2?:string = undefined
}

/**
 * @export 
 * A MultilingualNotificationtestName Validation Object
 * @class ValidationObjectMultilingualNotificationtestName
 */
export class ValidationObjectMultilingualNotificationtestName {
   sNotificationtestName1 = {
      type: 'string',
      required: false
   }
   sNotificationtestName2 = {
      type: 'string',
      required: false
   }
} 


