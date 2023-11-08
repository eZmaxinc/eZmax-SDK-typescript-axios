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
 * Payload for Websocket Information V1
 * @export
 * @interface WebsocketResponseInformationV1MPayload
 */
export interface WebsocketResponseInformationV1MPayload {
    /**
     * Information message
     * @type {string}
     * @memberof WebsocketResponseInformationV1MPayload
     */
    'sInformationMessage': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebsocketResponseInformationV1MPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebsocketResponseInformationV1MPayload
 */
export class DataObjectWebsocketResponseInformationV1MPayload {
   sInformationMessage:string = ''
}

/**
 * @export 
 * A WebsocketResponseInformationV1MPayload Validation Object
 * @class ValidationObjectWebsocketResponseInformationV1MPayload
 */
export class ValidationObjectWebsocketResponseInformationV1MPayload {
   sInformationMessage = {
      type: 'string',
      required: true
   }
} 

