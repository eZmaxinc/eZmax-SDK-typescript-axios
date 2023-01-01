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
import { FieldECommunicationexternalrecipientType } from './field-ecommunicationexternalrecipient-type';
// May contain unused imports in some cases
// @ts-ignore
import { PhoneResponseCompound } from './phone-response-compound';

import { DefaultObject } from '../base'

/**
 * A Communicationexternalrecipient Object
 * @export
 * @interface CommunicationexternalrecipientResponse
 */
export interface CommunicationexternalrecipientResponse {
    /**
     * The unique ID of the Communicationexternalrecipient
     * @type {number}
     * @memberof CommunicationexternalrecipientResponse
     */
    'pkiCommunicationexternalrecipientID': number;
    /**
     * The email address.
     * @type {string}
     * @memberof CommunicationexternalrecipientResponse
     */
    'sEmailAddress'?: string;
    /**
     * 
     * @type {PhoneResponseCompound}
     * @memberof CommunicationexternalrecipientResponse
     */
    'objPhoneSms'?: PhoneResponseCompound;
    /**
     * 
     * @type {FieldECommunicationexternalrecipientType}
     * @memberof CommunicationexternalrecipientResponse
     */
    'eCommunicationexternalrecipientType': FieldECommunicationexternalrecipientType;
    /**
     * The Name of the Communicationexternalrecipient
     * @type {string}
     * @memberof CommunicationexternalrecipientResponse
     */
    'sCommunicationexternalrecipientName': string;
}
/**
 * A CommunicationexternalrecipientResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommunicationexternalrecipientResponse
 */
export class DefaultObjectCommunicationexternalrecipientResponse extends DefaultObject {
   pkiCommunicationexternalrecipientID:number = 0
   sEmailAddress?:string = undefined
   objPhoneSms?:Partial<PhoneResponseCompound> = undefined
   eCommunicationexternalrecipientType:FieldECommunicationexternalrecipientType = 'To'
   sCommunicationexternalrecipientName:string = ''
}


