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
    /*'pkiNotificationtestID': number;*/
    'pkiNotificationtestID': number;
    /**
     * The function name of the Notificationtest
     * @type {string}
     * @memberof NotificationtestGetElementsV1ResponseMPayload
     */
    /*'sNotificationtestFunction': string;*/
    'sNotificationtestFunction': string;
    /**
     * 
     * @type {Array<string>}
     * @memberof NotificationtestGetElementsV1ResponseMPayload
     */
    /*'a_sVariableobjectProperty': Array<string>;*/
    'a_sVariableobjectProperty': Array<string>;
    /**
     * 
     * @type {Array<{ [key: string]: any; }>}
     * @memberof NotificationtestGetElementsV1ResponseMPayload
     */
    /*'a_objVariableobject': Array<{ [key: string]: any; }>;*/
    'a_objVariableobject': Array<{ [key: string]: any; }>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A NotificationtestGetElementsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectNotificationtestGetElementsV1ResponseMPayload
 */
export class DataObjectNotificationtestGetElementsV1ResponseMPayload {
   pkiNotificationtestID:number = 0
   sNotificationtestFunction:string = ''
   a_sVariableobjectProperty:Array<string> = []
   a_objVariableobject:Array<{ [key: string]: any; }> = []
}

/**
 * @export 
 * A NotificationtestGetElementsV1ResponseMPayload Validation Object
 * @class ValidationObjectNotificationtestGetElementsV1ResponseMPayload
 */
export class ValidationObjectNotificationtestGetElementsV1ResponseMPayload {
   pkiNotificationtestID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sNotificationtestFunction = {
      type: 'string',
      required: true
   }
   a_sVariableobjectProperty = {
      type: 'array',
      required: true
   }
   a_objVariableobject = {
      type: 'array',
      required: true
   }
} 


