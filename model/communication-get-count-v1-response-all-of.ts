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
import { CommunicationGetCountV1ResponseMPayload } from './communication-get-count-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface CommunicationGetCountV1ResponseAllOf
 */
export interface CommunicationGetCountV1ResponseAllOf {
    /**
     * 
     * @type {CommunicationGetCountV1ResponseMPayload}
     * @memberof CommunicationGetCountV1ResponseAllOf
     */
    'mPayload': CommunicationGetCountV1ResponseMPayload;
}
/**
 * A CommunicationGetCountV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommunicationGetCountV1ResponseAllOf
 */
export class DefaultObjectCommunicationGetCountV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<CommunicationGetCountV1ResponseMPayload> = {}
}


