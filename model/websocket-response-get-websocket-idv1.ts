/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { WebsocketResponseGetWebsocketIDV1MPayload } from './websocket-response-get-websocket-idv1-mpayload';

/**
 * Response for Websocket GetWebsocketID V1
 * @export
 * @interface WebsocketResponseGetWebsocketIDV1
 */
export interface WebsocketResponseGetWebsocketIDV1 {
    /**
     * The Type of message
     * @type {string}
     * @memberof WebsocketResponseGetWebsocketIDV1
     */
    /*'eWebsocketMessagetype': WebsocketResponseGetWebsocketIDV1EWebsocketMessagetypeEnum;*/
    'eWebsocketMessagetype': WebsocketResponseGetWebsocketIDV1EWebsocketMessagetypeEnum;
    /**
     * 
     * @type {WebsocketResponseGetWebsocketIDV1MPayload}
     * @memberof WebsocketResponseGetWebsocketIDV1
     */
    /*'mPayload': WebsocketResponseGetWebsocketIDV1MPayload;*/
    'mPayload': WebsocketResponseGetWebsocketIDV1MPayload;
}

export const WebsocketResponseGetWebsocketIDV1EWebsocketMessagetypeEnum = {
    Response_GetWebsocketID_V1: 'Response-GetWebsocketID-V1'
} as const;
export type WebsocketResponseGetWebsocketIDV1EWebsocketMessagetypeEnum = typeof WebsocketResponseGetWebsocketIDV1EWebsocketMessagetypeEnum[keyof typeof WebsocketResponseGetWebsocketIDV1EWebsocketMessagetypeEnum];


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebsocketResponseGetWebsocketIDV1MPayload } from './'
// @ts-ignore
import { ValidationObjectWebsocketResponseGetWebsocketIDV1MPayload } from './'

/**
 * @export 
 * A WebsocketResponseGetWebsocketIDV1 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebsocketResponseGetWebsocketIDV1
 */
export class DataObjectWebsocketResponseGetWebsocketIDV1 {
   eWebsocketMessagetype:WebsocketResponseGetWebsocketIDV1EWebsocketMessagetypeEnum = 'Response-GetWebsocketID-V1'
   mPayload:WebsocketResponseGetWebsocketIDV1MPayload = new DataObjectWebsocketResponseGetWebsocketIDV1MPayload()
}

/**
 * @export 
 * A WebsocketResponseGetWebsocketIDV1 Validation Object
 * @class ValidationObjectWebsocketResponseGetWebsocketIDV1
 */
export class ValidationObjectWebsocketResponseGetWebsocketIDV1 {
   eWebsocketMessagetype = {
      type: 'string',
      required: true
   }
   mPayload = new ValidationObjectWebsocketResponseGetWebsocketIDV1MPayload()
} 


