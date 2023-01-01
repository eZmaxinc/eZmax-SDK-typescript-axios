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
import { CommunicationGetListV1ResponseMPayload } from './communication-get-list-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface CommunicationGetListV1ResponseAllOf
 */
export interface CommunicationGetListV1ResponseAllOf {
    /**
     * 
     * @type {CommunicationGetListV1ResponseMPayload}
     * @memberof CommunicationGetListV1ResponseAllOf
     */
    'mPayload': CommunicationGetListV1ResponseMPayload;
}
/**
 * A CommunicationGetListV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommunicationGetListV1ResponseAllOf
 */
export class DefaultObjectCommunicationGetListV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<CommunicationGetListV1ResponseMPayload> = {}
}


