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


// May contain unused imports in some cases
// @ts-ignore
import { WebsocketResponseErrorV1MPayload } from './websocket-response-error-v1-mpayload';

/**
 * Response for Websocket Error V1
 * @export
 * @interface WebsocketResponseErrorV1
 */
export interface WebsocketResponseErrorV1 {
    /**
     * The Type of message
     * @type {string}
     * @memberof WebsocketResponseErrorV1
     */
    'eWebsocketMessagetype': WebsocketResponseErrorV1EWebsocketMessagetypeEnum;
    /**
     * 
     * @type {WebsocketResponseErrorV1MPayload}
     * @memberof WebsocketResponseErrorV1
     */
    'mPayload': WebsocketResponseErrorV1MPayload;
}

export const WebsocketResponseErrorV1EWebsocketMessagetypeEnum = {
    Response_Error_V1: 'Response-Error-V1'
} as const;
export type WebsocketResponseErrorV1EWebsocketMessagetypeEnum = typeof WebsocketResponseErrorV1EWebsocketMessagetypeEnum[keyof typeof WebsocketResponseErrorV1EWebsocketMessagetypeEnum];


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebsocketResponseErrorV1MPayload } from './'
// @ts-ignore
import { ValidationObjectWebsocketResponseErrorV1MPayload } from './'

/**
 * @export 
 * A WebsocketResponseErrorV1 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebsocketResponseErrorV1
 */
export class DataObjectWebsocketResponseErrorV1 {
   eWebsocketMessagetype:WebsocketResponseErrorV1EWebsocketMessagetypeEnum = 'Response-Error-V1'
   mPayload:WebsocketResponseErrorV1MPayload = new DataObjectWebsocketResponseErrorV1MPayload()
}

/**
 * @export 
 * A WebsocketResponseErrorV1 Validation Object
 * @class ValidationObjectWebsocketResponseErrorV1
 */
export class ValidationObjectWebsocketResponseErrorV1 {
   eWebsocketMessagetype = {
      type: 'string',
      required: true
   }
   mPayload = new ValidationObjectWebsocketResponseErrorV1MPayload()
} 

