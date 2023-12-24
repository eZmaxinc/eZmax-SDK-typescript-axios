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
import { WebsocketResponseInformationV1MPayload } from './websocket-response-information-v1-mpayload';

/**
 * Response for Websocket Information V1
 * @export
 * @interface WebsocketResponseInformationV1
 */
export interface WebsocketResponseInformationV1 {
    /**
     * The Type of message
     * @type {string}
     * @memberof WebsocketResponseInformationV1
     */
    'eWebsocketMessagetype': WebsocketResponseInformationV1EWebsocketMessagetypeEnum;
    /**
     * The Channel on which to route the websocket message
     * @type {string}
     * @memberof WebsocketResponseInformationV1
     */
    'sWebsocketChannel': string;
    /**
     * 
     * @type {WebsocketResponseInformationV1MPayload}
     * @memberof WebsocketResponseInformationV1
     */
    'mPayload': WebsocketResponseInformationV1MPayload;
}

export const WebsocketResponseInformationV1EWebsocketMessagetypeEnum = {
    Response_Information_V1: 'Response-Information-V1'
} as const;
export type WebsocketResponseInformationV1EWebsocketMessagetypeEnum = typeof WebsocketResponseInformationV1EWebsocketMessagetypeEnum[keyof typeof WebsocketResponseInformationV1EWebsocketMessagetypeEnum];


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebsocketResponseInformationV1MPayload } from './'
// @ts-ignore
import { ValidationObjectWebsocketResponseInformationV1MPayload } from './'

/**
 * @export 
 * A WebsocketResponseInformationV1 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebsocketResponseInformationV1
 */
export class DataObjectWebsocketResponseInformationV1 {
   eWebsocketMessagetype:WebsocketResponseInformationV1EWebsocketMessagetypeEnum = 'Response-Information-V1'
   sWebsocketChannel:string = ''
   mPayload:WebsocketResponseInformationV1MPayload = new DataObjectWebsocketResponseInformationV1MPayload()
}

/**
 * @export 
 * A WebsocketResponseInformationV1 Validation Object
 * @class ValidationObjectWebsocketResponseInformationV1
 */
export class ValidationObjectWebsocketResponseInformationV1 {
   eWebsocketMessagetype = {
      type: 'string',
      required: true
   }
   sWebsocketChannel = {
      type: 'string',
      pattern: '/^[a-zA-Z0-9_@.]{32}$/',
      required: true
   }
   mPayload = new ValidationObjectWebsocketResponseInformationV1MPayload()
} 


