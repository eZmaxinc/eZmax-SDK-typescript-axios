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


// May contain unused imports in some cases
// @ts-ignore
import { DescriptionstaticResponseCompound } from './descriptionstatic-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EmailstaticResponseCompound } from './emailstatic-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationexternalrecipientType } from './field-ecommunicationexternalrecipient-type';
// May contain unused imports in some cases
// @ts-ignore
import { PhonestaticResponseCompound } from './phonestatic-response-compound';

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
     * 
     * @type {FieldECommunicationexternalrecipientType}
     * @memberof CommunicationexternalrecipientResponse
     */
    'eCommunicationexternalrecipientType': FieldECommunicationexternalrecipientType;
    /**
     * 
     * @type {DescriptionstaticResponseCompound}
     * @memberof CommunicationexternalrecipientResponse
     */
    'objDescriptionstatic': DescriptionstaticResponseCompound;
    /**
     * 
     * @type {EmailstaticResponseCompound}
     * @memberof CommunicationexternalrecipientResponse
     */
    'objEmailstatic'?: EmailstaticResponseCompound;
    /**
     * 
     * @type {PhonestaticResponseCompound}
     * @memberof CommunicationexternalrecipientResponse
     */
    'objPhonestatic'?: PhonestaticResponseCompound;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectDescriptionstaticResponseCompound } from './'
// @ts-ignore
import { DataObjectEmailstaticResponseCompound } from './'
// @ts-ignore
import { DataObjectPhonestaticResponseCompound } from './'
// @ts-ignore
import { ValidationObjectDescriptionstaticResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEmailstaticResponseCompound } from './'
// @ts-ignore
import { ValidationObjectPhonestaticResponseCompound } from './'

/**
 * @export 
 * A CommunicationexternalrecipientResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationexternalrecipientResponse
 */
export class DataObjectCommunicationexternalrecipientResponse {
   pkiCommunicationexternalrecipientID:number = 0
   eCommunicationexternalrecipientType:FieldECommunicationexternalrecipientType = 'To'
   objDescriptionstatic:DescriptionstaticResponseCompound = new DataObjectDescriptionstaticResponseCompound()
   objEmailstatic?:EmailstaticResponseCompound = undefined
   objPhonestatic?:PhonestaticResponseCompound = undefined
}

/**
 * @export 
 * A CommunicationexternalrecipientResponse Validation Object
 * @class ValidationObjectCommunicationexternalrecipientResponse
 */
export class ValidationObjectCommunicationexternalrecipientResponse {
   pkiCommunicationexternalrecipientID = {
      type: 'integer',
      required: true
   }
   eCommunicationexternalrecipientType = {
      type: 'enum',
      allowableValues: ['To','Cc','Bcc'],
      required: true
   }
   objDescriptionstatic = new ValidationObjectDescriptionstaticResponseCompound()
   objEmailstatic = new ValidationObjectEmailstaticResponseCompound()
   objPhonestatic = new ValidationObjectPhonestaticResponseCompound()
} 


