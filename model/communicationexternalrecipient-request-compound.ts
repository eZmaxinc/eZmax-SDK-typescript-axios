/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommunicationexternalrecipientRequest } from './communicationexternalrecipient-request';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldECommunicationexternalrecipientType } from './field-ecommunicationexternalrecipient-type';

/**
 * @type CommunicationexternalrecipientRequestCompound
 * A Communicationexternalrecipient Object and children
 * @export
 */
/*export type CommunicationexternalrecipientRequestCompound = CommunicationexternalrecipientRequest;*/
export interface CommunicationexternalrecipientRequestCompound {
    /**
     * The unique ID of the Communicationexternalrecipient
     * @type {number}
     * @memberof CommunicationexternalrecipientRequestCompound
     */
    pkiCommunicationexternalrecipientID?:number 
    /**
     * The email address.
     * @type {string}
     * @memberof CommunicationexternalrecipientRequestCompound
     */
    sEmailAddress?:string 
    /**
     * A phone number in E.164 Format
     * @type {string}
     * @memberof CommunicationexternalrecipientRequestCompound
     */
    sPhoneE164?:string 
    /**
     * 
     * @type {FieldECommunicationexternalrecipientType}
     * @memberof CommunicationexternalrecipientRequestCompound
     */
    eCommunicationexternalrecipientType?:FieldECommunicationexternalrecipientType 
    /**
     * The name of the Communicationexternalrecipient
     * @type {string}
     * @memberof CommunicationexternalrecipientRequestCompound
     */
    sCommunicationexternalrecipientName?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommunicationexternalrecipientRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationexternalrecipientRequestCompound
 */
export class DataObjectCommunicationexternalrecipientRequestCompound {
    pkiCommunicationexternalrecipientID?:number = undefined
    sEmailAddress?:string = undefined
    sPhoneE164?:string = undefined
    eCommunicationexternalrecipientType?:FieldECommunicationexternalrecipientType = undefined
    sCommunicationexternalrecipientName?:string = undefined
}

/**
 * @export 
 * A CommunicationexternalrecipientRequestCompound Validation Object
 * @class ValidationObjectCommunicationexternalrecipientRequestCompound
 */
export class ValidationObjectCommunicationexternalrecipientRequestCompound {
   pkiCommunicationexternalrecipientID = {
      type: 'integer',
      required: false
   }
   sEmailAddress = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: false
   }
   sPhoneE164 = {
      type: 'string',
      pattern: /^\+[1-9]\d{1,14}$/,
      required: false
   }
   eCommunicationexternalrecipientType = {
      type: 'enum',
      allowableValues: ['To','Cc','Bcc'],
      required: false
   }
   sCommunicationexternalrecipientName = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
} 


