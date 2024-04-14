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
import { ComputedECommunicationDirection } from './computed-ecommunication-direction';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationImportance } from './field-ecommunication-importance';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationType } from './field-ecommunication-type';

/**
 * A Communication List Element
 * @export
 * @interface CustomCommunicationListElementResponse
 */
export interface CustomCommunicationListElementResponse {
    /**
     * The unique ID of the Communication.
     * @type {number}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'pkiCommunicationID': number;*/
    'pkiCommunicationID': number;
    /**
     * The date and time at which the object was created
     * @type {string}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'dtCreatedDate': string;*/
    'dtCreatedDate': string;
    /**
     * 
     * @type {ComputedECommunicationDirection}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'eCommunicationDirection': ComputedECommunicationDirection;*/
    'eCommunicationDirection': ComputedECommunicationDirection;
    /**
     * 
     * @type {FieldECommunicationImportance}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'eCommunicationImportance': FieldECommunicationImportance;*/
    'eCommunicationImportance': FieldECommunicationImportance;
    /**
     * 
     * @type {FieldECommunicationType}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'eCommunicationType': FieldECommunicationType;*/
    'eCommunicationType': FieldECommunicationType;
    /**
     * The count of Communicationrecipient
     * @type {number}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'iCommunicationrecipientCount': number;*/
    'iCommunicationrecipientCount': number;
    /**
     * The subject of the Communication
     * @type {string}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'sCommunicationSubject': string;*/
    'sCommunicationSubject': string;
    /**
     * The sender name of the Communication
     * @type {string}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'sCommunicationSender': string;*/
    'sCommunicationSender': string;
    /**
     * The recipients\' name of the Communication
     * @type {string}
     * @memberof CustomCommunicationListElementResponse
     */
    /*'sCommunicationRecipient': string;*/
    'sCommunicationRecipient': string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomCommunicationListElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomCommunicationListElementResponse
 */
export class DataObjectCustomCommunicationListElementResponse {
   pkiCommunicationID:number = 0
   dtCreatedDate:string = ''
   eCommunicationDirection:ComputedECommunicationDirection = 'Outbound'
   eCommunicationImportance:FieldECommunicationImportance = 'High'
   eCommunicationType:FieldECommunicationType = 'Email'
   iCommunicationrecipientCount:number = 0
   sCommunicationSubject:string = ''
   sCommunicationSender:string = ''
   sCommunicationRecipient:string = ''
}

/**
 * @export 
 * A CustomCommunicationListElementResponse Validation Object
 * @class ValidationObjectCustomCommunicationListElementResponse
 */
export class ValidationObjectCustomCommunicationListElementResponse {
   pkiCommunicationID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   dtCreatedDate = {
      type: 'string',
      required: true
   }
   eCommunicationDirection = {
      type: 'enum',
      allowableValues: ['Outbound','Inbound'],
      required: true
   }
   eCommunicationImportance = {
      type: 'enum',
      allowableValues: ['High','Normal','Low'],
      required: true
   }
   eCommunicationType = {
      type: 'enum',
      allowableValues: ['Email','Fax','Sms'],
      required: true
   }
   iCommunicationrecipientCount = {
      type: 'integer',
      required: true
   }
   sCommunicationSubject = {
      type: 'string',
      pattern: '/^.{0,200}$/',
      required: true
   }
   sCommunicationSender = {
      type: 'string',
      required: true
   }
   sCommunicationRecipient = {
      type: 'string',
      required: true
   }
} 


