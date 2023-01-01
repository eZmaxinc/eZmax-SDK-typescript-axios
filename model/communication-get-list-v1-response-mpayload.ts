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
import { CommunicationListElement } from './communication-list-element';

import { DefaultObject } from '../base'

/**
 * Payload for GET /1/module/communication/getList
 * @export
 * @interface CommunicationGetListV1ResponseMPayload
 */
export interface CommunicationGetListV1ResponseMPayload {
    /**
     * 
     * @type {Array<CommunicationListElement>}
     * @memberof CommunicationGetListV1ResponseMPayload
     */
    'a_objCommunication': Array<CommunicationListElement>;
}
/**
 * A CommunicationGetListV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommunicationGetListV1ResponseMPayload
 */
export class DefaultObjectCommunicationGetListV1ResponseMPayload extends DefaultObject {
   a_objCommunication:Array<CommunicationListElement> = []
}


