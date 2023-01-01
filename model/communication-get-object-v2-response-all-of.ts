/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommunicationGetObjectV2ResponseMPayload } from './communication-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface CommunicationGetObjectV2ResponseAllOf
 */
export interface CommunicationGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {CommunicationGetObjectV2ResponseMPayload}
     * @memberof CommunicationGetObjectV2ResponseAllOf
     */
    'mPayload': CommunicationGetObjectV2ResponseMPayload;
}
/**
 * A CommunicationGetObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommunicationGetObjectV2ResponseAllOf
 */
export class DefaultObjectCommunicationGetObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<CommunicationGetObjectV2ResponseMPayload> = {}
}


