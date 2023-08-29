/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for Websocket GetWebsocketID V1
 * @export
 * @interface WebsocketRequestServerGetWebsocketIDV1
 */
export interface WebsocketRequestServerGetWebsocketIDV1 {
    /**
     * The Type of message
     * @type {string}
     * @memberof WebsocketRequestServerGetWebsocketIDV1
     */
    'eWebsocketMessagetype': WebsocketRequestServerGetWebsocketIDV1EWebsocketMessagetypeEnum;
}

export const WebsocketRequestServerGetWebsocketIDV1EWebsocketMessagetypeEnum = {
    RequestServer_GetWebsocketID_V1: 'RequestServer-GetWebsocketID-V1'
} as const;
export type WebsocketRequestServerGetWebsocketIDV1EWebsocketMessagetypeEnum = typeof WebsocketRequestServerGetWebsocketIDV1EWebsocketMessagetypeEnum[keyof typeof WebsocketRequestServerGetWebsocketIDV1EWebsocketMessagetypeEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebsocketRequestServerGetWebsocketIDV1 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebsocketRequestServerGetWebsocketIDV1
 */
export class DataObjectWebsocketRequestServerGetWebsocketIDV1 {
   eWebsocketMessagetype:WebsocketRequestServerGetWebsocketIDV1EWebsocketMessagetypeEnum = 'RequestServer-GetWebsocketID-V1'
}

/**
 * @export 
 * A WebsocketRequestServerGetWebsocketIDV1 Validation Object
 * @class ValidationObjectWebsocketRequestServerGetWebsocketIDV1
 */
export class ValidationObjectWebsocketRequestServerGetWebsocketIDV1 {
   eWebsocketMessagetype = {
      type: 'string',
      required: true
   }
} 


